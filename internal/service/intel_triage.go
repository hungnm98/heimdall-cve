package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

// ---- finding assessments (agent triage) ----

var decisions = []model.Decision{
	model.DecisionFixNow, model.DecisionSchedule, model.DecisionMonitor, model.DecisionNotAffected, model.DecisionFalsePositive,
}

// minRationale is the rationale length that stands in for evidence URLs.
const minRationale = 20

// assessable reports a finding agents can assess: a dependency finding with
// an advisory and a package.
func assessable(f model.Finding) bool {
	return f.Kind == model.KindDependency && f.AdvisoryID != "" && f.Package.Name != ""
}

func assessmentKey(f model.Finding, repoSpecific bool) model.AssessmentKey {
	k := model.AssessmentKey{AdvisoryID: f.AdvisoryID, Ecosystem: f.Package.Ecosystem, Package: f.Package.Name, Version: f.Package.Version}
	if repoSpecific {
		k.Repo = f.Repo
	}
	return k
}

// assessmentInputsHash fingerprints the finding facts that would change an
// agent's answer. EPSS is bucketed to 0.1 so daily jitter does not
// invalidate assessments.
func assessmentInputsHash(f model.Finding) string {
	fixed := slices.Clone(f.FixedVersions)
	sort.Strings(fixed)
	s := fmt.Sprintf("v1|%s|%.1f|%t|%t|%.1f|%s", f.Severity, f.CVSSScore, f.InKEV, f.Malicious,
		math.Round(f.EPSS*10)/10, strings.Join(fixed, ","))
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:12])
}

// latestByKey loads the assessments that apply to findings, by key.
func (s *intelSvc) latestByKey(ctx context.Context, findings []model.Finding) (map[model.AssessmentKey]model.FindingAssessment, error) {
	keys := make([]model.AssessmentKey, 0, len(findings))
	for _, f := range findings {
		if assessable(f) {
			keys = append(keys, assessmentKey(f, true))
		}
	}
	out := map[model.AssessmentKey]model.FindingAssessment{}
	if len(keys) == 0 {
		return out, nil
	}
	as, err := s.st.LatestAssessments(ctx, keys)
	if err != nil {
		return nil, err
	}
	for _, a := range as {
		out[a.Key()] = a
	}
	return out, nil
}

// pickAssessment returns the assessment that applies to f: repo-specific
// first, then repo-agnostic.
func pickAssessment(byKey map[model.AssessmentKey]model.FindingAssessment, f model.Finding) (model.FindingAssessment, bool) {
	k := assessmentKey(f, true)
	if a, ok := byKey[k]; ok {
		return a, true
	}
	k.Repo = ""
	a, ok := byKey[k]
	return a, ok
}

// staleness says why a is not fresh for f, or "" when it is fresh.
func staleness(a model.FindingAssessment, f model.Finding, now time.Time, staleAfter time.Duration) string {
	if a.InputsHash != assessmentInputsHash(f) {
		return "finding changed since the last assessment (severity, CVSS, KEV, malicious, EPSS or fix versions)"
	}
	if age := now.Sub(a.AssessedAt); age > staleAfter {
		return fmt.Sprintf("last assessed %d days ago", int(age.Hours()/24))
	}
	return ""
}

func (s *intelSvc) LatestAssessments(ctx context.Context, findings []model.Finding, staleAfter time.Duration) (map[string]AssessmentStatus, error) {
	if staleAfter <= 0 {
		staleAfter = DefaultStaleAfter
	}
	byKey, err := s.latestByKey(ctx, findings)
	if err != nil {
		return nil, err
	}
	now := s.now()
	out := make(map[string]AssessmentStatus, len(byKey))
	for _, f := range findings {
		if !assessable(f) {
			continue
		}
		if a, ok := pickAssessment(byKey, f); ok {
			out[f.ID] = AssessmentStatus{Assessment: a, Fresh: staleness(a, f, now, staleAfter) == ""}
		}
	}
	return out, nil
}

// TriageQueue makes one pass over open dependency findings and one batched
// lookup of their latest assessments.
func (s *intelSvc) TriageQueue(ctx context.Context, f TriageFilter) ([]TriageItem, error) {
	minSev := model.SeverityHigh
	if f.MinSeverity != "" {
		if minSev = model.ParseSeverity(string(f.MinSeverity)); minSev == model.SeverityUnknown {
			return nil, invalid("min_severity", "must be CRITICAL, HIGH, MEDIUM or LOW")
		}
	}
	limit := ClampLimit(f.Limit)
	staleAfter := f.StaleAfter
	if staleAfter <= 0 {
		staleAfter = DefaultStaleAfter
	}
	// MinSeverity is applied here, not in the store: KEV and malicious
	// findings are queued at any severity.
	var cands []model.Finding
	err := eachFinding(ctx, s.d.Store, store.FindingFilter{Status: model.StatusOpen, Kind: model.KindDependency, Repo: f.Repo, InKEV: f.KEVOnly},
		func(x model.Finding) {
			if assessable(x) && (x.Severity.AtLeast(minSev) || x.InKEV || x.Malicious) {
				cands = append(cands, x)
			}
		})
	if err != nil {
		return nil, err
	}
	byKey, err := s.latestByKey(ctx, cands)
	if err != nil {
		return nil, err
	}

	type group struct {
		key   model.AssessmentKey
		item  TriageItem
		repos map[string]bool
	}
	groups := map[model.AssessmentKey]*group{}
	now := s.now()
	for _, x := range cands {
		gk, reason := assessmentKey(x, false), "never assessed"
		a, ok := pickAssessment(byKey, x)
		if ok {
			if reason = staleness(a, x, now, staleAfter); reason == "" {
				continue
			}
			gk.Repo = a.Repo // a stale repo-specific assessment keeps its repo apart
		}
		g := groups[gk]
		if g == nil {
			g = &group{key: gk, item: TriageItem{Finding: x, Reason: reason}, repos: map[string]bool{}}
			if ok {
				g.item.LastAssessment = &a
			}
			groups[gk] = g
		} else if x.Priority > g.item.Finding.Priority {
			g.item.Finding = x
		}
		g.repos[x.Repo] = true
	}

	all := make([]*group, 0, len(groups))
	for _, g := range groups {
		g.item.Repos = sortedSet(g.repos)
		notes := []string{g.item.Reason}
		if g.item.Finding.InKEV {
			notes = append(notes, "in CISA KEV")
		}
		if g.item.Finding.Malicious {
			notes = append(notes, "malicious package")
		}
		g.item.Reason = strings.Join(append(notes, plural(len(g.item.Repos), "repo")), "; ")
		all = append(all, g)
	}
	sort.Slice(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if a.item.Finding.Priority != b.item.Finding.Priority {
			return a.item.Finding.Priority > b.item.Finding.Priority
		}
		ka, kb := a.key, b.key
		switch {
		case ka.AdvisoryID != kb.AdvisoryID:
			return ka.AdvisoryID < kb.AdvisoryID
		case ka.Ecosystem != kb.Ecosystem:
			return ka.Ecosystem < kb.Ecosystem
		case ka.Package != kb.Package:
			return ka.Package < kb.Package
		case ka.Version != kb.Version:
			return ka.Version < kb.Version
		}
		return ka.Repo < kb.Repo
	})
	out := make([]TriageItem, 0, min(limit, len(all)))
	for _, g := range all[:min(limit, len(all))] {
		out = append(out, g.item)
	}
	return out, nil
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (s *intelSvc) loadAssessable(ctx context.Context, findingID string) (*model.Finding, error) {
	id := strings.TrimSpace(findingID)
	if id == "" {
		return nil, invalid("finding_id", "required")
	}
	f, err := s.d.Store.GetFinding(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("finding %q: %w", id, err)
	}
	if !assessable(*f) {
		return nil, invalid("finding_id", "only dependency findings with an advisory can be assessed")
	}
	return f, nil
}

func (s *intelSvc) SubmitAssessment(ctx context.Context, actor Actor, in AssessmentInput) (*model.FindingAssessment, error) {
	if err := s.writesAllowed(); err != nil {
		return nil, err
	}
	f, err := s.loadAssessable(ctx, in.FindingID)
	if err != nil {
		return nil, err
	}
	fe := fieldErrors{}
	decision := model.Decision(strings.ToLower(strings.TrimSpace(string(in.Decision))))
	if !slices.Contains(decisions, decision) {
		fe.add("decision", "must be one of fix-now, schedule, monitor, not-affected, false-positive")
	}
	if math.IsNaN(in.Score) || in.Score < 0 || in.Score > 100 {
		fe.add("score", "0 to 100")
	}
	rationale := strings.TrimSpace(in.Rationale)
	n := len([]rune(rationale))
	if n > maxSummary {
		fe.add("rationale", fmt.Sprintf("at most %d characters", maxSummary))
	}
	evidence := evidenceURLs(fe, in.Evidence)
	if len(evidence) == 0 && n < minRationale {
		fe.add("evidence", fmt.Sprintf("give at least one https URL, or a rationale of at least %d characters", minRationale))
	}
	conf := checkConfidence(fe, in.Confidence)
	if err := fe.err(); err != nil {
		return nil, err
	}
	k := assessmentKey(*f, in.RepoSpecific)
	a := &model.FindingAssessment{
		AdvisoryID: k.AdvisoryID, Ecosystem: k.Ecosystem, Package: k.Package, Version: k.Version, Repo: k.Repo,
		Decision: decision, Score: in.Score, Rationale: rationale, Evidence: evidence, Confidence: conf,
		InputsHash: assessmentInputsHash(*f), AssessedBy: actorName(actor), AssessedAt: s.now(),
	}
	if err := s.st.SaveAssessment(ctx, a); err != nil {
		return nil, err
	}
	s.audit(ctx, actor, "agent.assessment.submit", "finding", f.ID, map[string]any{
		"assessment_id": a.ID, "advisory_id": a.AdvisoryID, "package": string(a.Ecosystem) + "/" + a.Package + "@" + a.Version,
		"repo": a.Repo, "decision": string(decision), "score": a.Score, "confidence": string(conf), "evidence": evidence,
	})
	return a, nil
}

func (s *intelSvc) Assessments(ctx context.Context, findingID string, limit int) ([]model.FindingAssessment, error) {
	f, err := s.loadAssessable(ctx, findingID)
	if err != nil {
		return nil, err
	}
	return s.st.AssessmentHistory(ctx, assessmentKey(*f, true), ClampLimit(limit))
}
