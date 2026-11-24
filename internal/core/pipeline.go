package core

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/config"
	"github.com/hungnm98/heimdall-cve/internal/core/dedup"
	"github.com/hungnm98/heimdall-cve/internal/core/recommend"
	"github.com/hungnm98/heimdall-cve/internal/ecosystem"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/notify"
	"github.com/hungnm98/heimdall-cve/internal/report"
	"github.com/hungnm98/heimdall-cve/internal/runtime"
	"github.com/hungnm98/heimdall-cve/internal/source"
	"github.com/hungnm98/heimdall-cve/internal/store"
	"github.com/hungnm98/heimdall-cve/internal/vcs"
)

// Pipeline implements Scanner on top of the ports. Every field except Store
// and ProviderFor may be empty.
type Pipeline struct {
	Store   store.Store
	Catalog store.Catalog // optional: caches repo listings and scanned HEADs for the UI
	// ProviderFor returns the VCS provider serving a target (config or catalog credentials).
	ProviderFor func(ctx context.Context, t model.Target) (vcs.Provider, error)

	Ecosystems     []ecosystem.Ecosystem
	Detectors      []runtime.Detector
	VulnSources    []source.VulnSource
	RuntimeSources []source.RuntimeSource
	Enrichers      []source.Enricher
	Notifiers      []notify.Notifier
	Reporters      []report.Reporter

	Policy      config.Policy
	SkipPaths   []string // path prefixes ("vendor/") skipped anywhere in the tree
	Concurrency int      // repos scanned in parallel (default 4)
	ReportDir   string   // when set, every reporter writes run-<id><ext> there
	UIBaseURL   string   // optional, for links in notifications

	Logger *slog.Logger
	Now    func() time.Time
}

var _ Scanner = (*Pipeline)(nil)

// repoResult is what scanning one repo produced before sources are queried.
type repoResult struct {
	repo     model.Repo
	prov     vcs.Provider // the target's provider: reads code with its credentials
	targetID int64
	sha      string
	graphs   []model.DependencyGraph
	runtimes []model.Runtime
	errs     []string
	failed   bool
}

// Scan runs one scan. Failures of single repos or sources make the run
// partial; only setup errors (store) fail it.
func (p *Pipeline) Scan(ctx context.Context, req ScanRequest, prog Progress) (*model.ScanRun, error) {
	if prog == nil {
		prog = Discard
	}
	run := &model.ScanRun{StartedAt: p.now()}
	for _, t := range req.Targets {
		run.Targets = append(run.Targets, t.String())
	}
	if err := p.Store.StartRun(ctx, run); err != nil {
		return nil, fmt.Errorf("start run: %w", err)
	}
	err := p.scan(ctx, req, prog, run)
	run.FinishedAt = p.now()
	switch {
	case err != nil:
		run.Status, run.Error = model.RunFailed, err.Error()
	case len(run.ReposFailed) > 0 || unhealthy(run.Sources):
		run.Status = model.RunPartial
	default:
		run.Status = model.RunSucceeded
	}
	// Record the outcome even when ctx was canceled.
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if ferr := p.Store.FinishRun(fctx, run); ferr != nil && err == nil {
		err = fmt.Errorf("finish run: %w", ferr)
	}
	prog.Event("info", "", fmt.Sprintf("run %d %s: %d repos scanned, %d failed, %d new, %d fixed",
		run.ID, run.Status, len(run.ReposScanned), len(run.ReposFailed), run.Stats.New, run.Stats.Fixed))
	return run, err
}

func (p *Pipeline) scan(ctx context.Context, req ScanRequest, prog Progress, run *model.ScanRun) error {
	if len(p.VulnSources) == 0 {
		prog.Event("warn", "", "no vulnerability source is enabled: dependencies will not be checked (enable sources.osv)")
	}
	repos := p.resolve(ctx, req, prog, run)
	if err := ctx.Err(); err != nil {
		return err
	}
	results := p.fetchAll(ctx, repos, prog)
	if err := ctx.Err(); err != nil {
		return err
	}
	cmps := dedup.Comparators{}
	for _, e := range p.Ecosystems {
		cmps[e.Name()] = e.Versions()
	}

	// Standard library vulnerabilities come from the declared Go versions.
	for _, r := range results {
		r.graphs = append(r.graphs, stdlibGraphs(r.runtimes)...)
	}

	advisories := p.queryVulns(ctx, results, prog, run)
	statuses := p.evaluateRuntimes(ctx, results, prog, run)

	var all []model.Finding
	reports := make([]model.RepoReport, 0, len(results))
	for _, r := range results {
		if r.failed {
			run.ReposFailed = append(run.ReposFailed, r.repo.FullName())
			reports = append(reports, model.RepoReport{Repo: r.repo, HeadSHA: r.sha, Errors: r.errs})
			continue
		}
		run.ReposScanned = append(run.ReposScanned, r.repo.FullName())
		loc := dedup.Location{Provider: r.repo.Provider, Repo: r.repo.FullName()}
		fs := dedup.Findings(loc, r.graphs, advisories, cmps)
		fs = append(fs, runtimeFindings(r, statuses)...)
		fs = p.applyPolicy(fs)
		all = append(all, fs...)
		reports = append(reports, model.RepoReport{Repo: r.repo, HeadSHA: r.sha, Runtimes: repoStatuses(r, statuses), Errors: r.errs})
	}

	ptrs := make([]*model.Finding, len(all))
	for i := range all {
		ptrs[i] = &all[i]
	}
	for _, e := range p.Enrichers {
		start := time.Now()
		err := e.Enrich(ctx, ptrs)
		run.Sources = append(run.Sources, health(e.Name(), err, 1, start))
		if err != nil {
			prog.Event("warn", "", fmt.Sprintf("enricher %s failed: %v", e.Name(), err))
		}
	}
	recommend.Apply(all, cmps)

	now := p.now()
	diff, err := p.Store.RecordFindings(ctx, run.ID, run.ReposScanned, all, now)
	if err != nil {
		return fmt.Errorf("record findings: %w", err)
	}
	p.markScanned(ctx, results, now)

	run.Stats = stats(all, diff, len(run.ReposScanned))
	// Reports show what is open now, with lifecycle fields from the store
	// (FirstSeen, suppressed findings left out).
	byRepo := map[string][]model.Finding{}
	for _, f := range append(append([]model.Finding{}, diff.New...), diff.StillOpen...) {
		byRepo[f.Repo] = append(byRepo[f.Repo], f)
	}
	for i := range reports {
		fs := byRepo[reports[i].Repo.FullName()]
		reports[i].Findings = fs
		reports[i].UpgradePlan = recommend.Plan(fs, cmps)
	}
	rep := &model.Report{Run: *run, GeneratedAt: now, Repos: reports, Diff: diff}
	p.writeReports(rep, prog)
	p.notify(ctx, rep, all, prog)
	return nil
}

// ---- resolve & fetch ----

func (p *Pipeline) resolve(ctx context.Context, req ScanRequest, prog Progress, run *model.ScanRun) []repoResult {
	var out []repoResult
	seen := map[string]bool{}
	for _, t := range req.Targets {
		prov, err := p.ProviderFor(ctx, t)
		if err != nil {
			prog.Event("error", "", fmt.Sprintf("%s: %v", t, err))
			run.ReposFailed = append(run.ReposFailed, t.String())
			continue
		}
		prog.Event("info", "", fmt.Sprintf("listing %s", t))
		repos, err := prov.ListRepos(ctx, t)
		if err != nil {
			prog.Event("error", "", fmt.Sprintf("list %s: %v", t, err))
			run.ReposFailed = append(run.ReposFailed, t.String())
			continue
		}
		tid := req.TargetIDs[t.String()]
		if p.Catalog != nil && tid != 0 {
			if err := p.Catalog.UpsertRepos(ctx, tid, repos, p.now()); err != nil {
				p.log().Warn("cache repo list", "target", t.String(), "err", err)
			}
		}
		for _, r := range repos {
			if req.Repo != "" && r.FullName() != req.Repo {
				continue
			}
			if seen[r.FullName()] { // listed by two targets: scan once
				continue
			}
			seen[r.FullName()] = true
			out = append(out, repoResult{repo: r, prov: prov, targetID: tid})
		}
		if req.Repo != "" && len(out) == 0 {
			prog.Event("warn", req.Repo, fmt.Sprintf("%s is not part of %s", req.Repo, t))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].repo.FullName() < out[j].repo.FullName() })
	prog.Event("info", "", fmt.Sprintf("%d repos to scan", len(out)))
	return out
}

func (p *Pipeline) fetchAll(ctx context.Context, repos []repoResult, prog Progress) []*repoResult {
	out := make([]*repoResult, len(repos))
	n := p.Concurrency
	if n <= 0 {
		n = 4
	}
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for i := range repos {
		r := repos[i]
		out[i] = &r
		wg.Add(1)
		sem <- struct{}{}
		go func(r *repoResult) {
			defer wg.Done()
			defer func() { <-sem }()
			p.fetchRepo(ctx, r, prog)
		}(out[i])
	}
	wg.Wait()
	return out
}

func (p *Pipeline) fetchRepo(ctx context.Context, r *repoResult, prog Progress) {
	name := r.repo.FullName()
	fail := func(format string, a ...any) {
		msg := fmt.Sprintf(format, a...)
		r.errs, r.failed = append(r.errs, msg), true
		prog.Event("error", name, msg)
	}
	prov := r.prov
	sha, err := prov.ResolveRef(ctx, r.repo, r.repo.Ref)
	if err != nil {
		fail("resolve %s: %v", r.repo.Ref, err)
		return
	}
	r.sha = sha
	paths, err := prov.ListFiles(ctx, r.repo, sha)
	if err != nil {
		fail("list files: %v", err)
		return
	}
	wanted := map[string]bool{}
	for _, f := range paths {
		if p.skipped(f) {
			continue
		}
		for _, e := range p.Ecosystems {
			if e.Match(f) {
				wanted[f] = true
			}
		}
		for _, d := range p.Detectors {
			if d.Match(f) {
				wanted[f] = true
			}
		}
	}
	files := model.FileSet{Files: map[string][]byte{}}
	for f := range wanted {
		b, err := prov.ReadFile(ctx, r.repo, sha, f)
		if err != nil {
			r.errs = append(r.errs, fmt.Sprintf("read %s: %v", f, err))
			continue
		}
		files.Files[f] = b
	}
	for _, e := range p.Ecosystems {
		sub := subset(files, e.Match)
		if len(sub.Files) == 0 {
			continue
		}
		gs, err := e.Parse(ctx, sub)
		// Parsers return the graphs they could build plus an error naming the
		// bad files: keep both.
		if err != nil {
			r.errs = append(r.errs, fmt.Sprintf("%s: %v", e.Name(), err))
			prog.Event("warn", name, fmt.Sprintf("%s: %v", e.Name(), err))
		}
		for _, g := range gs {
			r.graphs = append(r.graphs, *g)
		}
	}
	for _, d := range p.Detectors {
		sub := subset(files, d.Match)
		if len(sub.Files) == 0 {
			continue
		}
		rts, err := d.Detect(ctx, sub)
		if err != nil {
			r.errs = append(r.errs, fmt.Sprintf("%s: %v", d.Name(), err))
		}
		r.runtimes = append(r.runtimes, rts...)
	}
	deps := 0
	for _, g := range r.graphs {
		deps += len(g.Dependencies)
	}
	prog.Event("info", name, fmt.Sprintf("%s@%.7s: %d manifests, %d dependencies, %d runtime declarations",
		r.repo.Ref, sha, len(r.graphs), deps, len(r.runtimes)))
}

func (p *Pipeline) skipped(f string) bool {
	for _, s := range p.SkipPaths {
		s = strings.TrimSuffix(s, "/") + "/"
		if strings.HasPrefix(f, s) || strings.Contains(f, "/"+s) {
			return true
		}
	}
	return false
}

func subset(fs model.FileSet, match func(string) bool) model.FileSet {
	out := model.FileSet{Files: map[string][]byte{}}
	for k, v := range fs.Files {
		if match(k) {
			out.Files[k] = v
		}
	}
	return out
}

// ---- sources ----

func (p *Pipeline) queryVulns(ctx context.Context, results []*repoResult, prog Progress, run *model.ScanRun) []model.Advisory {
	// One batch per run: every distinct public package across repos.
	byEco := map[model.Ecosystem]map[string]model.Package{}
	for _, r := range results {
		for _, g := range r.graphs {
			for _, d := range g.Dependencies {
				if d.Private || d.Unresolvable != "" {
					continue
				}
				if byEco[d.Ecosystem] == nil {
					byEco[d.Ecosystem] = map[string]model.Package{}
				}
				byEco[d.Ecosystem][d.PURL] = d.Package
			}
		}
	}
	var advs []model.Advisory
	for _, s := range p.VulnSources {
		var pkgs []model.Package
		for eco, m := range byEco {
			if !s.Supports(eco) {
				continue
			}
			for _, pk := range m {
				pkgs = append(pkgs, pk)
			}
		}
		if len(pkgs) == 0 {
			continue
		}
		sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].PURL < pkgs[j].PURL })
		start := time.Now()
		got, err := s.Query(ctx, pkgs)
		run.Sources = append(run.Sources, health(s.Name(), err, 1, start))
		if err != nil {
			prog.Event("warn", "", fmt.Sprintf("source %s failed: %v", s.Name(), err))
			continue
		}
		prog.Event("info", "", fmt.Sprintf("source %s: %d packages, %d advisories", s.Name(), len(pkgs), len(got)))
		advs = append(advs, got...)
	}
	return dedup.Merge(advs)
}

type rtKey struct{ name, version string }

func (p *Pipeline) evaluateRuntimes(ctx context.Context, results []*repoResult, prog Progress, run *model.ScanRun) map[rtKey]*model.RuntimeStatus {
	out := map[rtKey]*model.RuntimeStatus{}
	calls, errs := map[string]int{}, map[string]error{}
	start := time.Now()
	for _, r := range results {
		for _, rt := range r.runtimes {
			k := rtKey{rt.Name, rt.Version}
			if _, done := out[k]; done {
				continue
			}
			for _, s := range p.RuntimeSources {
				if !s.Supports(rt.Name) {
					continue
				}
				calls[s.Name()]++
				st, err := s.Evaluate(ctx, rt)
				if err != nil {
					errs[s.Name()] = err
					continue
				}
				out[k] = st
				break
			}
		}
	}
	for name, n := range calls {
		run.Sources = append(run.Sources, health(name, errs[name], n, start))
		if errs[name] != nil {
			prog.Event("warn", "", fmt.Sprintf("runtime source %s: %v", name, errs[name]))
		}
	}
	return out
}

// stdlibGraphs turns exact Go versions (x.y.z) into synthetic "stdlib"
// dependencies so the standard library is checked like any module. A bare
// "go 1.22" directive is a minimum, not the toolchain in use: skipped.
func stdlibGraphs(rts []model.Runtime) []model.DependencyGraph {
	byOrigin := map[string]map[string]bool{}
	for _, rt := range rts {
		if rt.Name != "go" || strings.Count(rt.Version, ".") < 2 {
			continue
		}
		if byOrigin[rt.Origin] == nil {
			byOrigin[rt.Origin] = map[string]bool{}
		}
		byOrigin[rt.Origin][rt.Version] = true
	}
	var out []model.DependencyGraph
	for origin, vs := range byOrigin {
		g := model.DependencyGraph{Ecosystem: model.EcosystemGo, ManifestPath: origin}
		for v := range vs {
			g.Dependencies = append(g.Dependencies, model.Dependency{
				Package: model.NewPackage(model.EcosystemGo, "stdlib", v), Direct: true, Scope: model.ScopeProd,
			})
		}
		sort.Slice(g.Dependencies, func(i, j int) bool { return g.Dependencies[i].Version < g.Dependencies[j].Version })
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ManifestPath < out[j].ManifestPath })
	return out
}

// runtimeFindings reports EOL and soon-EOL runtimes, one per declaration.
func runtimeFindings(r *repoResult, statuses map[rtKey]*model.RuntimeStatus) []model.Finding {
	var out []model.Finding
	for _, rt := range r.runtimes {
		st := statuses[rtKey{rt.Name, rt.Version}]
		if st == nil || (st.Status != model.SupportEOL && st.Status != model.SupportEOLSoon) {
			continue
		}
		s := *st
		s.Runtime = rt
		sev, what := model.SeverityMedium, "reaches end of life soon"
		if st.Status == model.SupportEOL {
			sev, what = model.SeverityHigh, "is end of life"
		}
		f := model.Finding{
			Kind: model.KindRuntime, Provider: r.repo.Provider, Repo: r.repo.FullName(), ManifestPath: rt.Origin,
			AdvisoryID: fmt.Sprintf("EOL-%s-%s", rt.Name, s.Cycle),
			Summary:    fmt.Sprintf("%s %s (%s in %s) %s", rt.Name, rt.Version, rt.Via, rt.Origin, what),
			Severity:   sev, Runtime: &s, Sources: []string{st.Source}, Verified: true, Scope: model.ScopeProd,
		}
		f.ComputeID()
		out = append(out, f)
	}
	return out
}

func repoStatuses(r *repoResult, statuses map[rtKey]*model.RuntimeStatus) []model.RuntimeStatus {
	var out []model.RuntimeStatus
	for _, rt := range r.runtimes {
		if st := statuses[rtKey{rt.Name, rt.Version}]; st != nil {
			s := *st
			s.Runtime = rt
			out = append(out, s)
			continue
		}
		out = append(out, model.RuntimeStatus{Runtime: rt, Status: model.SupportUnknown})
	}
	return out
}

// applyPolicy drops dev-scope findings when configured and computes priority.
func (p *Pipeline) applyPolicy(fs []model.Finding) []model.Finding {
	out := fs[:0]
	for _, f := range fs {
		if p.Policy.IgnoreDevDeps && f.Scope == model.ScopeDev {
			continue
		}
		f.Priority = priority(f)
		out = append(out, f)
	}
	return out
}

// priority: KEV and malicious first, then severity, EPSS, direct and prod.
func priority(f model.Finding) float64 {
	score := float64(f.Severity.Rank()) * 10
	if f.CVSSScore > 0 {
		score = f.CVSSScore * 10
	}
	if f.EPSS > 0 {
		score *= 1 + f.EPSS
	}
	if !f.Direct {
		score *= 0.8
	}
	if f.Scope == model.ScopeDev {
		score *= 0.3
	}
	if f.InKEV || f.Malicious {
		score += 1000
	}
	return score
}

func (p *Pipeline) markScanned(ctx context.Context, results []*repoResult, at time.Time) {
	for _, r := range results {
		if r.failed {
			continue
		}
		name := r.repo.FullName()
		if err := p.Store.PutRepoState(ctx, model.RepoState{Repo: name, Ref: r.repo.Ref, HeadSHA: r.sha, ScannedAt: at}); err != nil {
			p.log().Warn("save repo state", "repo", name, "err", err)
		}
		if p.Catalog != nil && r.targetID != 0 {
			if err := p.Catalog.MarkRepoScanned(ctx, name, r.sha, at); err != nil && !errors.Is(err, store.ErrNotFound) {
				p.log().Warn("mark repo scanned", "repo", name, "err", err)
			}
		}
	}
}

func stats(all []model.Finding, d *model.Diff, repos int) model.RunStats {
	st := model.RunStats{OpenBySeverity: map[model.Severity]int{}, Repos: repos}
	if d != nil {
		st.New, st.Fixed = len(d.New), len(d.Fixed)
		for _, f := range append(append([]model.Finding{}, d.New...), d.StillOpen...) {
			st.OpenBySeverity[f.Severity]++
		}
		return st
	}
	for _, f := range all {
		st.OpenBySeverity[f.Severity]++
	}
	return st
}

func health(name string, err error, calls int, start time.Time) model.SourceHealth {
	h := model.SourceHealth{Name: name, Healthy: err == nil, Calls: calls, Duration: time.Since(start)}
	if err != nil {
		h.Error = err.Error()
	}
	return h
}

func unhealthy(hs []model.SourceHealth) bool {
	for _, h := range hs {
		if !h.Healthy {
			return true
		}
	}
	return false
}

func (p *Pipeline) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Pipeline) log() *slog.Logger {
	if p.Logger != nil {
		return p.Logger
	}
	return slog.New(slog.DiscardHandler)
}
