package service

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

// Agent advisory ids. Public prefixes belong to databases agents do not own;
// a public id an agent knows about goes into aliases instead.
const AgentAdvisoryPrefix = "HEIMDALL-AGENT-"

var publicIDPrefixes = []string{"GHSA-", "CVE-", "GO-", "OSV-", "MAL-", "PYSEC-", "RUSTSEC-", "BIT-"}

var advisoryIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{2,99}$`)

const (
	// DefaultStaleAfter is how old an analysis may be before it is redone.
	DefaultStaleAfter = 30 * 24 * time.Hour
	// queueScanLimit bounds the libraries AnalysisQueue considers (the most
	// used first), so a huge inventory costs one bounded pass.
	queueScanLimit = 5000
	maxEvidence    = 20
	maxSummary     = 4000
)

type intelSvc struct {
	*base
	st store.Intel
	// idMu serialises id generation within this process. Two processes
	// generating at the same instant could still pick the same number (the
	// second save would replace the first); agents rarely submit concurrently.
	idMu sync.Mutex
}

func (s *intelSvc) writesAllowed() error {
	if s.d.Config == nil || !s.d.Config.MCP.AllowAgentWrites {
		return fmt.Errorf("agent writes (mcp.allow_agent_writes): %w", ErrForbidden)
	}
	return nil
}

func (s *intelSvc) Inventory(ctx context.Context, f store.InventoryFilter) ([]model.InventoryItem, error) {
	if f.Ecosystem != "" {
		eco, ok := parseEcosystem(string(f.Ecosystem))
		if !ok {
			return nil, invalid("ecosystem", "must be go, npm or rubygems")
		}
		f.Ecosystem = eco
	}
	f.Limit = ClampLimit(f.Limit)
	return s.st.ListInventory(ctx, f)
}

func (s *intelSvc) Analyses(ctx context.Context, eco model.Ecosystem, name string, limit int) ([]model.LibraryAnalysis, error) {
	fe := fieldErrors{}
	e, ok := parseEcosystem(string(eco))
	if !ok {
		fe.add("ecosystem", "must be go, npm or rubygems")
	}
	if strings.TrimSpace(name) == "" {
		fe.add("name", "required")
	}
	if err := fe.err(); err != nil {
		return nil, err
	}
	return s.st.AnalysisHistory(ctx, e, strings.TrimSpace(name), ClampLimit(limit))
}

// Queue scoring weights.
const (
	scoreNeverAnalyzed = 100.0
	scoreStale         = 60.0
	scoreNewVersion    = 25.0 // a version in use that the last analysis did not cover
	scoreDirect        = 20.0
	scorePerRepo       = 5.0 // capped at maxRepoScore
	maxRepoScore       = 50.0
	maxFindingScore    = 60.0
)

var findingWeight = map[model.Severity]float64{
	model.SeverityCritical: 15, model.SeverityHigh: 8, model.SeverityMedium: 3, model.SeverityLow: 1, model.SeverityUnknown: 1,
}

// AnalysisQueue ranks public libraries in use. A library analyzed less than
// staleAfter ago whose versions in use were all covered is left out: there is
// nothing new to analyze. Work is bounded: at most queueScanLimit libraries
// (the most used), one pass over latest analyses and one over open findings.
func (s *intelSvc) AnalysisQueue(ctx context.Context, limit int, staleAfter time.Duration) ([]QueueItem, error) {
	limit = ClampLimit(limit)
	if staleAfter <= 0 {
		staleAfter = DefaultStaleAfter
	}
	usage, err := s.st.PackageUsage(ctx, store.UsageFilter{Limit: queueScanLimit})
	if err != nil {
		return nil, err
	}
	if len(usage) == 0 {
		return []QueueItem{}, nil
	}
	type key struct {
		eco  model.Ecosystem
		name string
	}
	inUse := make(map[key]bool, len(usage))
	for _, u := range usage {
		inUse[key{u.Ecosystem, u.Name}] = true
	}
	latestList, err := s.st.LatestAnalyses(ctx, store.AnalysisFilter{})
	if err != nil {
		return nil, err
	}
	latest := map[key]model.LibraryAnalysis{}
	for _, a := range latestList {
		if k := (key{a.Ecosystem, a.Name}); inUse[k] {
			latest[k] = a
		}
	}
	type sevCount map[model.Severity]int
	findings := map[key]sevCount{}
	err = eachFinding(ctx, s.d.Store, store.FindingFilter{Status: model.StatusOpen, Kind: model.KindDependency, DefaultBranchOnly: true}, func(f model.Finding) {
		k := key{f.Package.Ecosystem, f.Package.Name}
		if !inUse[k] {
			return
		}
		if findings[k] == nil {
			findings[k] = sevCount{}
		}
		findings[k][f.Severity]++
	})
	if err != nil {
		return nil, err
	}

	now := s.now()
	out := make([]QueueItem, 0, min(limit*2, len(usage)))
	for _, u := range usage {
		k := key{u.Ecosystem, u.Name}
		item := QueueItem{Usage: u}
		var reasons []string
		if a, ok := latest[k]; !ok {
			item.Score += scoreNeverAnalyzed
			reasons = append(reasons, "never analyzed")
		} else {
			a := a
			item.LastAnalysis = &a
			fresh := true
			if age := now.Sub(a.AnalyzedAt); age > staleAfter {
				item.Score += scoreStale
				reasons = append(reasons, fmt.Sprintf("last analyzed %d days ago", int(age.Hours()/24)))
				fresh = false
			}
			if a.Version != "" && slices.ContainsFunc(u.Versions, func(v string) bool { return v != a.Version }) {
				item.Score += scoreNewVersion
				reasons = append(reasons, "versions in use not covered by the last analysis ("+a.Version+")")
				fresh = false
			}
			if fresh {
				continue
			}
		}
		if u.Direct {
			item.Score += scoreDirect
			reasons = append(reasons, "direct dependency")
		}
		item.Score += min(scorePerRepo*float64(len(u.Repos)), maxRepoScore)
		reasons = append(reasons, plural(len(u.Repos), "repo"))
		if sc := findings[k]; len(sc) > 0 {
			var fscore float64
			var parts []string
			for _, sev := range []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityUnknown} {
				if n := sc[sev]; n > 0 {
					item.OpenFindings += n
					fscore += findingWeight[sev] * float64(n)
					parts = append(parts, fmt.Sprintf("%d %s", n, sev))
				}
			}
			item.Score += min(fscore, maxFindingScore)
			reasons = append(reasons, plural(item.OpenFindings, "open finding")+" ("+strings.Join(parts, ", ")+")")
		}
		item.Reason = strings.Join(reasons, "; ")
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case a.Score != b.Score:
			return a.Score > b.Score
		case len(a.Usage.Repos) != len(b.Usage.Repos):
			return len(a.Usage.Repos) > len(b.Usage.Repos)
		case a.Usage.Ecosystem != b.Usage.Ecosystem:
			return a.Usage.Ecosystem < b.Usage.Ecosystem
		}
		return a.Usage.Name < b.Usage.Name
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
}

func (s *intelSvc) SubmitAdvisory(ctx context.Context, actor Actor, in AdvisoryInput) (*model.AgentAdvisory, error) {
	if err := s.writesAllowed(); err != nil {
		return nil, err
	}
	rec, err := decodeOSV(in.OSV)
	if err != nil {
		return nil, err
	}
	fe := fieldErrors{}
	id := strings.TrimSpace(rec.ID)
	switch {
	case id == "":
		// generated below, once the rest is valid
	case hasPublicPrefix(id):
		fe.add("osv_json.id", fmt.Sprintf("%q is a public database id: put it in aliases and use an id starting with %s (or omit id to get one)", id, AgentAdvisoryPrefix))
	case !strings.HasPrefix(id, AgentAdvisoryPrefix) || !advisoryIDPattern.MatchString(id):
		fe.add("osv_json.id", "must start with "+AgentAdvisoryPrefix+" (letters, digits, . _ - only), or be omitted to get a generated one")
	}
	adv := model.Advisory{
		ID:      id,
		Summary: strings.TrimSpace(rec.Summary),
		Details: strings.TrimSpace(rec.Details),
	}
	if adv.Summary == "" && adv.Details == "" {
		fe.add("osv_json.summary", "a summary or details is required")
	}
	if len([]rune(adv.Summary)) > 500 || len([]rune(adv.Details)) > 20000 {
		fe.add("osv_json.summary", "summary max 500 characters, details max 20000")
	}
	seen := map[string]bool{id: true}
	for _, a := range rec.Aliases {
		a = strings.TrimSpace(a)
		if a == "" || seen[a] {
			continue
		}
		if !advisoryIDPattern.MatchString(a) {
			fe.add("osv_json.aliases", fmt.Sprintf("invalid alias %q", a))
			continue
		}
		seen[a] = true
		adv.Aliases = append(adv.Aliases, a)
	}
	if len(adv.Aliases) > 20 {
		fe.add("osv_json.aliases", "at most 20 aliases")
	}
	if len(rec.Affected) == 0 {
		fe.add("osv_json.affected", "at least one affected package (Go, npm or RubyGems) with ranges or versions is required")
	}
	for i, a := range rec.Affected {
		m, msg := a.toModel()
		if msg != "" {
			fe.add(fmt.Sprintf("osv_json.affected[%d]", i), msg)
			continue
		}
		adv.Affected = append(adv.Affected, m)
	}
	adv.Severity, adv.CVSSVector, adv.CVSSScore = rec.severity()
	if adv.Severity == model.SeverityUnknown {
		fe.add("osv_json.severity", `give a CVSS_V3 vector in severity[] or a label in database_specific.severity (LOW, MEDIUM, HIGH, CRITICAL)`)
	}
	for _, r := range rec.References {
		if u := strings.TrimSpace(r.URL); u != "" {
			if !isWebURL(u, false) {
				fe.add("osv_json.references", fmt.Sprintf("invalid reference URL %q", u))
				continue
			}
			adv.References = append(adv.References, u)
		}
	}
	evidence := checkEvidence(fe, in.Evidence)
	conf := checkConfidence(fe, in.Confidence)
	if err := fe.err(); err != nil {
		return nil, err
	}

	now := s.now()
	adv.Published, adv.Modified, adv.Withdrawn = now, now, rec.Withdrawn
	if rec.Published != nil && !rec.Published.IsZero() {
		adv.Published = rec.Published.UTC()
	}
	adv.Sources, adv.Verified = []string{model.AgentSource}, false // never trusted until a public source confirms
	rec2 := &model.AgentAdvisory{Advisory: adv, Evidence: evidence, Confidence: conf, SubmittedBy: actorName(actor), SubmittedAt: now}

	s.idMu.Lock()
	generated := rec2.Advisory.ID == ""
	if generated {
		rec2.Advisory.ID, err = s.nextAdvisoryID(ctx, now.Year())
		if err != nil {
			s.idMu.Unlock()
			return nil, err
		}
	}
	err = s.st.SaveAgentAdvisory(ctx, rec2)
	s.idMu.Unlock()
	if err != nil {
		return nil, err
	}
	pkgs := make([]string, 0, len(adv.Affected))
	for _, a := range adv.Affected {
		pkgs = append(pkgs, string(a.Ecosystem)+"/"+a.Name)
	}
	s.audit(ctx, actor, "agent.advisory.submit", "advisory", rec2.Advisory.ID, map[string]any{
		"aliases": adv.Aliases, "packages": pkgs, "severity": string(adv.Severity),
		"confidence": string(conf), "evidence": evidence, "generated_id": generated,
	})
	return rec2, nil
}

// nextAdvisoryID returns HEIMDALL-AGENT-<year>-<n> with n one above the
// highest number used that year (zero-padded to 4 digits).
func (s *intelSvc) nextAdvisoryID(ctx context.Context, year int) (string, error) {
	all, err := s.st.ListAgentAdvisories(ctx)
	if err != nil {
		return "", err
	}
	prefix := fmt.Sprintf("%s%d-", AgentAdvisoryPrefix, year)
	maxN := 0
	for _, a := range all {
		if rest, ok := strings.CutPrefix(a.Advisory.ID, prefix); ok {
			if n, err := strconv.Atoi(rest); err == nil && n > maxN {
				maxN = n
			}
		}
	}
	return fmt.Sprintf("%s%04d", prefix, maxN+1), nil
}

func hasPublicPrefix(id string) bool {
	up := strings.ToUpper(id)
	for _, p := range publicIDPrefixes {
		if strings.HasPrefix(up, p) {
			return true
		}
	}
	return false
}

// isWebURL reports an absolute http(s) URL with a host; httpsOnly requires https.
func isWebURL(raw string, httpsOnly bool) bool {
	if len(raw) > 2000 {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Scheme == "https" || (!httpsOnly && u.Scheme == "http")
}

// checkEvidence requires 1..maxEvidence distinct https URLs.
func checkEvidence(fe fieldErrors, in []string) []string {
	out := evidenceURLs(fe, in)
	if len(out) == 0 {
		fe.add("evidence", "at least one https URL is required")
	}
	return out
}

// evidenceURLs accepts 0..maxEvidence distinct https URLs.
func evidenceURLs(fe fieldErrors, in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, e := range in {
		e = strings.TrimSpace(e)
		if e == "" || seen[e] {
			continue
		}
		if !isWebURL(e, true) {
			fe.add("evidence", fmt.Sprintf("%q is not an https URL", e))
			continue
		}
		seen[e] = true
		out = append(out, e)
	}
	if len(out) > maxEvidence {
		fe.add("evidence", fmt.Sprintf("at most %d URLs", maxEvidence))
	}
	return out
}

func checkConfidence(fe fieldErrors, c model.Confidence) model.Confidence {
	switch v := model.Confidence(strings.ToLower(strings.TrimSpace(string(c)))); v {
	case model.ConfidenceLow, model.ConfidenceMedium, model.ConfidenceHigh:
		return v
	}
	fe.add("confidence", "must be low, medium or high")
	return ""
}

var verdicts = []model.Verdict{
	model.VerdictOK, model.VerdictSafeToBump, model.VerdictBreaking,
	model.VerdictAbandoned, model.VerdictSuspicious, model.VerdictMalicious,
}

func (s *intelSvc) SubmitAnalysis(ctx context.Context, actor Actor, in AnalysisInput) (*model.LibraryAnalysis, error) {
	if err := s.writesAllowed(); err != nil {
		return nil, err
	}
	fe := fieldErrors{}
	eco, ok := parseEcosystem(string(in.Ecosystem))
	if !ok {
		fe.add("ecosystem", "must be go, npm or rubygems")
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 300 {
		fe.add("name", "required, at most 300 characters")
	}
	version, rec := strings.TrimSpace(in.Version), strings.TrimSpace(in.RecommendedVersion)
	if len(version) > 100 {
		fe.add("version", "at most 100 characters")
	}
	if len(rec) > 100 {
		fe.add("recommended_version", "at most 100 characters")
	}
	verdict := model.Verdict(strings.ToLower(strings.TrimSpace(string(in.Verdict))))
	if !slices.Contains(verdicts, verdict) {
		fe.add("verdict", "must be one of ok, safe-to-bump, breaking-change, abandoned, suspicious-release, malicious")
	}
	summary := strings.TrimSpace(in.Summary)
	if n := len([]rune(summary)); n < 10 || n > maxSummary {
		fe.add("summary", fmt.Sprintf("10 to %d characters", maxSummary))
	}
	evidence := checkEvidence(fe, in.Evidence)
	conf := checkConfidence(fe, in.Confidence)
	if err := fe.err(); err != nil {
		return nil, err
	}
	a := &model.LibraryAnalysis{
		Ecosystem: eco, Name: name, Version: version, Verdict: verdict, Summary: summary,
		Evidence: evidence, RecommendedVersion: rec, Confidence: conf,
		Agent: actorName(actor), AnalyzedAt: s.now(),
	}
	if err := s.st.SaveAnalysis(ctx, a); err != nil {
		return nil, err
	}
	s.audit(ctx, actor, "agent.analysis.submit", "library", string(eco)+"/"+name, map[string]any{
		"analysis_id": a.ID, "version": version, "verdict": string(verdict), "confidence": string(conf),
		"recommended_version": rec, "evidence": evidence,
	})
	return a, nil
}
