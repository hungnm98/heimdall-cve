package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

type reposSvc struct{ *base }

func (s *reposSvc) List(ctx context.Context, f store.RepoFilter) (*Page[model.RepoRecord], error) {
	limit := ClampLimit(f.Limit)
	f.Limit = limit + 1
	items, err := s.d.Catalog.ListRepos(ctx, f)
	if err != nil {
		return nil, err
	}
	page := &Page[model.RepoRecord]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextCursor = items[limit-1].FullName()
	}
	for i := range page.Items {
		counts, err := s.openCounts(ctx, page.Items[i].FullName())
		if err != nil {
			return nil, err
		}
		page.Items[i].OpenBySeverity = counts
	}
	return page, nil
}

// openCounts counts a repo's open findings by severity (one page of repos
// at a time, so the cost is bounded by the page size).
func (s *reposSvc) openCounts(ctx context.Context, repo string) (map[model.Severity]int, error) {
	counts := map[model.Severity]int{}
	err := eachFinding(ctx, s.d.Store, store.FindingFilter{Repo: repo, Status: model.StatusOpen, DefaultBranchOnly: true}, func(f model.Finding) {
		counts[f.Severity]++
	})
	return counts, err
}

func (s *reposSvc) Get(ctx context.Context, fullName, branch string) (*RepoDetail, error) {
	rec, err := s.d.Catalog.GetRepo(ctx, fullName)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	var all, open []model.Finding
	err2 := eachFinding(ctx, s.d.Store, store.FindingFilter{Repo: fullName, Status: model.StatusOpen}, func(f model.Finding) {
		all = append(all, f)
		if f.Branch == branch {
			open = append(open, f)
		}
	})
	if err2 != nil {
		return nil, err2
	}
	if branch != "" && len(open) == 0 && !s.scannedBranch(ctx, fullName, branch) {
		return nil, fmt.Errorf("branch %s of %s: %w", branch, fullName, ErrNotFound)
	}
	if rec == nil {
		// Not in the cached listing (e.g. an ad-hoc repo scan): show it if it has findings.
		if len(open) == 0 {
			return nil, err
		}
		owner, name, _ := strings.Cut(fullName, "/")
		rec = &model.RepoRecord{Repo: model.Repo{Owner: owner, Name: name, Provider: open[0].Provider}}
	}
	d := &RepoDetail{Record: *rec, Branch: branch, Findings: open}
	if d.Branches, err = s.branches(ctx, *rec, all); err != nil {
		return nil, err
	}
	d.Record.OpenBySeverity = map[model.Severity]int{}
	for _, f := range open {
		d.Record.OpenBySeverity[f.Severity]++
	}
	for _, f := range open {
		if f.Kind == model.KindRuntime && f.Runtime != nil {
			d.Runtimes = append(d.Runtimes, *f.Runtime)
		}
	}
	d.UpgradePlan = upgradePlan(open)
	return d, nil
}

func (s *reposSvc) scannedBranch(ctx context.Context, repo, branch string) bool {
	_, err := s.d.Store.GetRepoState(ctx, repo, branch)
	return err == nil
}

// branches lists the scanned branches of rec with their open counts: the
// primary branch, branches with open findings, and branches scanned no
// earlier than the primary (a branch no longer scanned stops being updated).
func (s *reposSvc) branches(ctx context.Context, rec model.RepoRecord, open []model.Finding) ([]BranchStatus, error) {
	states, err := s.d.Store.ListRepoStates(ctx, rec.FullName())
	if err != nil {
		return nil, err
	}
	primary := rec.Ref
	if primary == "" {
		primary = rec.DefaultBranch
	}
	idx := map[string]int{}
	var out []BranchStatus
	get := func(name string) *BranchStatus {
		i, ok := idx[name]
		if !ok {
			i = len(out)
			idx[name] = i
			out = append(out, BranchStatus{Name: name, Primary: name == primary, OpenBySeverity: map[model.Severity]int{}})
		}
		return &out[i]
	}
	if primary != "" {
		get(primary)
	}
	for _, f := range open {
		name := f.Branch
		if name == "" {
			name = primary
		}
		get(name).OpenBySeverity[f.Severity]++
	}
	var primaryAt time.Time
	for _, st := range states {
		if st.Ref == primary {
			primaryAt = st.ScannedAt
		}
	}
	for _, st := range states {
		if _, ok := idx[st.Ref]; ok || !st.ScannedAt.Before(primaryAt) {
			b := get(st.Ref)
			b.HeadSHA, b.ScannedAt = st.HeadSHA, st.ScannedAt
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Primary != out[j].Primary {
			return out[i].Primary
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// upgradePlan folds dependency findings into one line per manifest+package,
// worst severity first.
func upgradePlan(findings []model.Finding) []model.UpgradeItem {
	idx := map[string]int{}
	var out []model.UpgradeItem
	for _, f := range findings {
		if f.Kind != model.KindDependency {
			continue
		}
		key := f.ManifestPath + "\x00" + f.Package.Key()
		i, ok := idx[key]
		if !ok {
			idx[key] = len(out)
			out = append(out, model.UpgradeItem{
				Package: f.Package, Manifest: f.ManifestPath, Direct: f.Direct, Severity: f.Severity,
				Recommended: f.RecommendedVersion, Bump: f.Bump, Advice: f.Advice,
			})
			i = len(out) - 1
		}
		it := &out[i]
		if f.AdvisoryID != "" {
			it.Advisories = append(it.Advisories, f.AdvisoryID)
		}
		if f.Severity.Rank() > it.Severity.Rank() {
			it.Severity = f.Severity
		}
		if it.Recommended == "" && f.RecommendedVersion != "" {
			it.Recommended, it.Bump, it.Advice = f.RecommendedVersion, f.Bump, f.Advice
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity.Rank() > out[j].Severity.Rank() })
	return out
}
