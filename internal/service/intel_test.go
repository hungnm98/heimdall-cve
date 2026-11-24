package service_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/config"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/notify"
	"github.com/hungnm98/heimdall-cve/internal/service"
	"github.com/hungnm98/heimdall-cve/internal/store"
	"github.com/hungnm98/heimdall-cve/internal/store/memstore"
)

type fakeNotifier struct {
	mu   sync.Mutex
	evs  []model.NotificationEvent
	fail error
}

func (f *fakeNotifier) Name() string { return "fake" }
func (f *fakeNotifier) Notify(_ context.Context, ev model.NotificationEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.evs = append(f.evs, ev)
	return nil
}

type intelEnv struct {
	st    *memstore.Store
	cfg   *config.Config
	notif *fakeNotifier
	svc   *service.Services
	now   time.Time
}

func newIntelEnv(t *testing.T, writes, notifyOn bool) *intelEnv {
	t.Helper()
	e := &intelEnv{st: memstore.New(), cfg: &config.Config{}, notif: &fakeNotifier{}, now: t0}
	e.cfg.MCP = config.MCPConfig{AllowAgentWrites: writes, AllowNotify: notifyOn, NotifyDailyLimit: 3}
	e.svc = service.New(service.Deps{
		Config: e.cfg, Store: e.st, Notifiers: []notify.Notifier{e.notif},
		Now: func() time.Time { return e.now },
	})
	return e
}

func inv(repo, name, version string, direct bool) model.InventoryItem {
	return model.InventoryItem{Repo: repo, ManifestPath: "package.json", Package: model.NewPackage(model.EcosystemNPM, name, version), Direct: direct}
}

func TestIntelNilWithoutStoreIntel(t *testing.T) {
	svc := service.New(service.Deps{Store: storeOnly{memstore.New()}})
	if svc.Intel != nil || svc.Messenger != nil {
		t.Fatal("Intel and Messenger must be nil when the store has no store.Intel")
	}
}

func TestAnalysisQueueRanking(t *testing.T) {
	e := newIntelEnv(t, true, false)
	ctx := context.Background()
	must(t, e.st.ReplaceInventory(ctx, "acme/web", []model.InventoryItem{
		inv("", "lodash", "4.17.15", true), inv("", "left-pad", "1.3.0", false), inv("", "react", "18.0.0", true),
		{ManifestPath: "package.json", Package: model.NewPackage(model.EcosystemNPM, "@acme/ui", "1.0.0"), Private: true, Direct: true},
	}, t0))
	must(t, e.st.ReplaceInventory(ctx, "acme/api", []model.InventoryItem{inv("", "lodash", "4.17.15", true), inv("", "react", "18.0.0", true)}, t0))
	// react was analyzed recently at the version in use: nothing to do.
	must(t, e.st.SaveAnalysis(ctx, &model.LibraryAnalysis{Ecosystem: model.EcosystemNPM, Name: "react", Version: "18.0.0", Verdict: model.VerdictOK, AnalyzedAt: t0.Add(-24 * time.Hour)}))
	// left-pad analysis is stale.
	must(t, e.st.SaveAnalysis(ctx, &model.LibraryAnalysis{Ecosystem: model.EcosystemNPM, Name: "left-pad", Version: "1.3.0", Verdict: model.VerdictOK, AnalyzedAt: t0.Add(-90 * 24 * time.Hour)}))
	// an open CRITICAL finding on left-pad.
	run := &model.ScanRun{StartedAt: t0}
	must(t, e.st.StartRun(ctx, run))
	f := model.Finding{Kind: model.KindDependency, Provider: "github", Repo: "acme/web", ManifestPath: "package.json",
		Package: model.NewPackage(model.EcosystemNPM, "left-pad", "1.3.0"), AdvisoryID: "GHSA-x", Severity: model.SeverityCritical}
	f.ComputeID()
	if _, err := e.st.RecordFindings(ctx, run.ID, []string{"acme/web"}, []model.Finding{f}, t0); err != nil {
		t.Fatal(err)
	}

	q, err := e.svc.Intel.AnalysisQueue(ctx, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, it := range q {
		names = append(names, it.Usage.Name)
		if it.Usage.Name == "@acme/ui" {
			t.Fatal("private packages must never be queued")
		}
	}
	if strings.Join(names, ",") != "lodash,left-pad" {
		t.Fatalf("queue = %v (want lodash: never analyzed, direct, 2 repos; then stale left-pad; react fresh → excluded)", names)
	}
	if q[0].LastAnalysis != nil || !strings.Contains(q[0].Reason, "never analyzed") || !strings.Contains(q[0].Reason, "2 repos") {
		t.Fatalf("lodash item %+v", q[0])
	}
	if q[1].OpenFindings != 1 || q[1].LastAnalysis == nil || !strings.Contains(q[1].Reason, "90 days") || !strings.Contains(q[1].Reason, "CRITICAL") {
		t.Fatalf("left-pad item %+v", q[1])
	}
	if q, _ := e.svc.Intel.AnalysisQueue(ctx, 1, 0); len(q) != 1 {
		t.Fatalf("limit ignored: %d", len(q))
	}
	// A new version in use re-queues a freshly analyzed library.
	must(t, e.st.ReplaceInventory(ctx, "acme/api", []model.InventoryItem{inv("", "react", "19.0.0", true)}, t0))
	q, _ = e.svc.Intel.AnalysisQueue(ctx, 10, 0)
	found := false
	for _, it := range q {
		if it.Usage.Name == "react" {
			found = strings.Contains(it.Reason, "not covered")
		}
	}
	if !found {
		t.Fatalf("react with a new version in use must be queued: %+v", q)
	}
}

const validOSV = `{
  "id": "HEIMDALL-AGENT-2026-0042",
  "aliases": ["CVE-2026-1234"],
  "summary": "left-pad 1.3.0 ships a credential stealer",
  "affected": [{"package": {"ecosystem": "npm", "name": "left-pad"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.3.0"}, {"fixed": "1.3.1"}]}]}],
  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
  "references": [{"type": "WEB", "url": "https://example.com/advisory"}]
}`

func TestSubmitAdvisory(t *testing.T) {
	ctx := context.Background()
	evidence := []string{"https://example.com/proof"}

	off := newIntelEnv(t, false, false)
	if _, err := off.svc.Intel.SubmitAdvisory(ctx, "mcp:test", service.AdvisoryInput{OSV: []byte(validOSV), Evidence: evidence, Confidence: "high"}); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("writes disabled: %v", err)
	}

	e := newIntelEnv(t, true, false)
	a, err := e.svc.Intel.SubmitAdvisory(ctx, "mcp:test", service.AdvisoryInput{OSV: []byte(validOSV), Evidence: evidence, Confidence: "High"})
	if err != nil {
		t.Fatal(err)
	}
	if a.Advisory.ID != "HEIMDALL-AGENT-2026-0042" || a.Advisory.Verified || len(a.Advisory.Sources) != 1 || a.Advisory.Sources[0] != model.AgentSource {
		t.Fatalf("advisory must be agent-sourced and unverified: %+v", a.Advisory)
	}
	if a.Advisory.Severity != model.SeverityCritical || a.Advisory.CVSSScore != 9.8 || a.Confidence != model.ConfidenceHigh || a.SubmittedBy != "mcp:test" {
		t.Fatalf("advisory %+v", a)
	}
	if r := a.Advisory.Affected[0]; r.Ecosystem != model.EcosystemNPM || r.Ranges[0] != (model.VersionRange{Introduced: "1.3.0", Fixed: "1.3.1"}) {
		t.Fatalf("affected %+v", r)
	}
	stored, _ := e.st.ListAgentAdvisories(ctx)
	if len(stored) != 1 {
		t.Fatalf("stored %d", len(stored))
	}

	// Generated ids: HEIMDALL-AGENT-<year>-<n>, above the highest used.
	noID := strings.Replace(validOSV, `"id": "HEIMDALL-AGENT-2026-0042",`, `"database_specific": {"severity": "moderate"},`, 1)
	noID = strings.Replace(noID, `"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],`, "", 1)
	a, err = e.svc.Intel.SubmitAdvisory(ctx, "mcp:test", service.AdvisoryInput{OSV: []byte(noID), Evidence: evidence, Confidence: "low"})
	if err != nil {
		t.Fatal(err)
	}
	if a.Advisory.ID != "HEIMDALL-AGENT-2026-0043" || a.Advisory.Severity != model.SeverityMedium {
		t.Fatalf("generated %q severity %s", a.Advisory.ID, a.Advisory.Severity)
	}

	cases := map[string]struct {
		osv      string
		evidence []string
		conf     model.Confidence
		field    string
	}{
		"public id":      {strings.Replace(validOSV, "HEIMDALL-AGENT-2026-0042", "GHSA-aaaa-bbbb-cccc", 1), evidence, "high", "osv_json.id"},
		"foreign id":     {strings.Replace(validOSV, "HEIMDALL-AGENT-2026-0042", "ACME-1", 1), evidence, "high", "osv_json.id"},
		"no evidence":    {validOSV, nil, "high", "evidence"},
		"http evidence":  {validOSV, []string{"http://example.com"}, "high", "evidence"},
		"bad confidence": {validOSV, evidence, "sure", "confidence"},
		"bad ecosystem":  {strings.Replace(validOSV, `"ecosystem": "npm"`, `"ecosystem": "PyPI"`, 1), evidence, "high", "osv_json.affected[0]"},
		"no ranges":      {strings.Replace(validOSV, `"ranges"`, `"x"`, 1), evidence, "high", "osv_json.affected[0]"},
		"no severity":    {strings.Replace(validOSV, `"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],`, "", 1), evidence, "high", "osv_json.severity"},
		"not json":       {"{", evidence, "high", "osv_json"},
		"empty affected": {strings.Replace(validOSV, `"affected"`, `"x"`, 1), evidence, "high", "osv_json.affected"},
	}
	for name, c := range cases {
		_, err := e.svc.Intel.SubmitAdvisory(ctx, "mcp:test", service.AdvisoryInput{OSV: []byte(c.osv), Evidence: c.evidence, Confidence: c.conf})
		if fieldsOf(t, err)[c.field] == "" {
			t.Errorf("%s: want field %q, got %v", name, c.field, err)
		}
	}
	if got := auditActions(t, e.st); strings.Join(got, ",") != "agent.advisory.submit,agent.advisory.submit" {
		t.Fatalf("audit %v", got)
	}
}

func TestSubmitAnalysis(t *testing.T) {
	ctx := context.Background()
	in := service.AnalysisInput{
		Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Verdict: "abandoned",
		Summary: "No release since 2018; maintainer archived the repo.", Evidence: []string{"https://github.com/left-pad/left-pad"},
		Confidence: "medium",
	}
	off := newIntelEnv(t, false, false)
	if _, err := off.svc.Intel.SubmitAnalysis(ctx, "mcp:x", in); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("disabled: %v", err)
	}
	e := newIntelEnv(t, true, false)
	a, err := e.svc.Intel.SubmitAnalysis(ctx, "mcp:x", in)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == 0 || a.Agent != "mcp:x" || a.Verdict != model.VerdictAbandoned || !a.AnalyzedAt.Equal(t0) {
		t.Fatalf("analysis %+v", a)
	}
	hist, err := e.svc.Intel.Analyses(ctx, "npm", "left-pad", 0)
	if err != nil || len(hist) != 1 {
		t.Fatalf("history %v %v", hist, err)
	}
	bad := service.AnalysisInput{Ecosystem: "pypi", Verdict: "great", Summary: "short", Confidence: "x"}
	f := fieldsOf(t, func() error { _, err := e.svc.Intel.SubmitAnalysis(ctx, "mcp:x", bad); return err }())
	for _, k := range []string{"ecosystem", "name", "verdict", "summary", "evidence", "confidence"} {
		if f[k] == "" {
			t.Errorf("missing field error %q in %v", k, f)
		}
	}
	if got := auditActions(t, e.st); strings.Join(got, ",") != "agent.analysis.submit" {
		t.Fatalf("audit %v", got)
	}
}

func TestNotifyUser(t *testing.T) {
	ctx := context.Background()
	msg := service.MessageInput{Title: "New CRITICAL in left-pad", Body: "Upgrade to 1.3.1.", Severity: "critical",
		Refs: []string{"https://example.com/a", "HEIMDALL-AGENT-2026-0001"}}

	off := newIntelEnv(t, false, false)
	if _, err := off.svc.Messenger.NotifyUser(ctx, "mcp:x", msg); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("disabled: %v", err)
	}

	e := newIntelEnv(t, false, true)
	sent, err := e.svc.Messenger.NotifyUser(ctx, "mcp:x", msg)
	if err != nil || !sent {
		t.Fatalf("first send: %v %v", sent, err)
	}
	if len(e.notif.evs) != 1 {
		t.Fatalf("delivered %d", len(e.notif.evs))
	}
	ev := e.notif.evs[0]
	if ev.Type != model.EventAgentMessage || ev.Severity != model.SeverityCritical || len(ev.Links) != 1 || !strings.Contains(ev.Body, "HEIMDALL-AGENT-2026-0001") {
		t.Fatalf("event %+v", ev)
	}
	// Identical message: deduplicated, not an error.
	sent, err = e.svc.Messenger.NotifyUser(ctx, "mcp:x", msg)
	if err != nil || sent {
		t.Fatalf("duplicate: %v %v", sent, err)
	}
	// Limit is 3 per day; the duplicate used a slot.
	msg.Title = "Another"
	if sent, err := e.svc.Messenger.NotifyUser(ctx, "mcp:x", msg); err != nil || !sent {
		t.Fatalf("third: %v %v", sent, err)
	}
	msg.Title = "Over the limit"
	if _, err := e.svc.Messenger.NotifyUser(ctx, "mcp:x", msg); !errors.Is(err, service.ErrRateLimited) {
		t.Fatalf("want rate limited, got %v", err)
	}
	// Next UTC day: slots are free again.
	e.now = t0.Add(24 * time.Hour)
	if sent, err := e.svc.Messenger.NotifyUser(ctx, "mcp:x", msg); err != nil || !sent {
		t.Fatalf("next day: %v %v", sent, err)
	}
	if len(e.notif.evs) != 3 {
		t.Fatalf("delivered %d, want 3", len(e.notif.evs))
	}
	if got := auditActions(t, e.st); strings.Join(got, ",") != "agent.notify,agent.notify,agent.notify,agent.notify,agent.notify" {
		t.Fatalf("audit %v", got)
	}
	// Validation.
	f := fieldsOf(t, func() error {
		_, err := e.svc.Messenger.NotifyUser(ctx, "mcp:x", service.MessageInput{Severity: "urgent"})
		return err
	}())
	for _, k := range []string{"title", "body", "severity"} {
		if f[k] == "" {
			t.Errorf("missing %q in %v", k, f)
		}
	}
	// Delivery failure surfaces as an upstream error.
	e.notif.fail = errors.New("slack down")
	var up *service.UpstreamError
	if _, err := e.svc.Messenger.NotifyUser(ctx, "mcp:x", service.MessageInput{Title: "t", Body: "b"}); !errors.As(err, &up) {
		t.Fatalf("want upstream error, got %v", err)
	}
}

// seedTriage records open findings: GHSA-1 on lodash 4.17.20 (HIGH) in three
// repos, a MEDIUM one, a LOW one in KEV and a runtime finding.
func seedTriage(t *testing.T, st *memstore.Store) map[string]model.Finding {
	t.Helper()
	ctx := context.Background()
	mk := func(repo, adv, name string, sev model.Severity, prio float64) model.Finding {
		f := model.Finding{Kind: model.KindDependency, Provider: "github", Repo: repo, ManifestPath: "package.json",
			Package: model.NewPackage(model.EcosystemNPM, name, "1.0.0"), AdvisoryID: adv, Severity: sev, CVSSScore: 7.5,
			EPSS: 0.12, FixedVersions: []string{"1.0.1"}, Priority: prio}
		f.ComputeID()
		return f
	}
	fs := map[string]model.Finding{
		"a":   mk("o/a", "GHSA-1", "lodash", model.SeverityHigh, 50),
		"b":   mk("o/b", "GHSA-1", "lodash", model.SeverityHigh, 60),
		"c":   mk("o/c", "GHSA-1", "lodash", model.SeverityHigh, 40),
		"med": mk("o/a", "GHSA-2", "axios", model.SeverityMedium, 30),
		"kev": mk("o/a", "GHSA-3", "left-pad", model.SeverityLow, 20),
	}
	kev := fs["kev"]
	kev.InKEV = true
	fs["kev"] = kev
	rt := model.Finding{Kind: model.KindRuntime, Provider: "github", Repo: "o/a", ManifestPath: ".nvmrc", AdvisoryID: "EOL-node-16",
		Severity: model.SeverityHigh, Priority: 90, Runtime: &model.RuntimeStatus{Runtime: model.Runtime{Name: "node", Version: "16"}, Status: model.SupportEOL}}
	rt.ComputeID()
	fs["rt"] = rt
	run := &model.ScanRun{StartedAt: t0}
	must(t, st.StartRun(ctx, run))
	all := make([]model.Finding, 0, len(fs))
	for _, f := range fs {
		all = append(all, f)
	}
	if _, err := st.RecordFindings(ctx, run.ID, []string{"o/a", "o/b", "o/c"}, all, t0); err != nil {
		t.Fatal(err)
	}
	return fs
}

func triageAdvisories(t *testing.T, e *intelEnv, f service.TriageFilter) []string {
	t.Helper()
	q, err := e.svc.Intel.TriageQueue(context.Background(), f)
	must(t, err)
	var out []string
	for _, it := range q {
		out = append(out, it.Finding.AdvisoryID+"@"+strings.Join(it.Repos, "+"))
	}
	return out
}

func TestTriageAndAssessments(t *testing.T) {
	ctx := context.Background()
	e := newIntelEnv(t, true, false)
	fs := seedTriage(t, e.st)

	// HIGH+ or KEV, dependency only; GHSA-1 collapses to one item led by the
	// highest-priority finding.
	q, err := e.svc.Intel.TriageQueue(ctx, service.TriageFilter{})
	must(t, err)
	if len(q) != 2 || q[0].Finding.ID != fs["b"].ID || strings.Join(q[0].Repos, ",") != "o/a,o/b,o/c" || q[0].LastAssessment != nil ||
		!strings.Contains(q[0].Reason, "never assessed") || !strings.Contains(q[0].Reason, "3 repos") {
		t.Fatalf("queue %+v", q)
	}
	if q[1].Finding.ID != fs["kev"].ID || !strings.Contains(q[1].Reason, "KEV") {
		t.Fatalf("KEV item %+v", q[1])
	}
	if got := triageAdvisories(t, e, service.TriageFilter{KEVOnly: true}); strings.Join(got, ",") != "GHSA-3@o/a" {
		t.Fatalf("kev only %v", got)
	}
	if got := triageAdvisories(t, e, service.TriageFilter{Repo: "o/c"}); strings.Join(got, ",") != "GHSA-1@o/c" {
		t.Fatalf("repo filter %v", got)
	}
	if got := triageAdvisories(t, e, service.TriageFilter{MinSeverity: "medium", Limit: 2}); strings.Join(got, ",") != "GHSA-1@o/a+o/b+o/c,GHSA-2@o/a" {
		t.Fatalf("min severity + limit %v", got)
	}
	if f := fieldsOf(t, func() error {
		_, err := e.svc.Intel.TriageQueue(ctx, service.TriageFilter{MinSeverity: "bogus"})
		return err
	}()); f["min_severity"] == "" {
		t.Fatalf("bad severity %v", f)
	}

	// Writes are gated; input is validated.
	in := service.AssessmentInput{FindingID: fs["a"].ID, Decision: "schedule", Score: 70, Rationale: "patch available, no known exploit",
		Evidence: []string{"https://github.com/advisories/GHSA-1"}, Confidence: "medium"}
	off := newIntelEnv(t, false, false)
	if _, err := off.svc.Intel.SubmitAssessment(ctx, "mcp:x", in); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("disabled: %v", err)
	}
	bad := service.AssessmentInput{FindingID: fs["a"].ID, Decision: "panic", Score: 101, Rationale: "short", Evidence: []string{"http://x.example"}, Confidence: "x"}
	f := fieldsOf(t, func() error { _, err := e.svc.Intel.SubmitAssessment(ctx, "mcp:x", bad); return err }())
	for _, k := range []string{"decision", "score", "evidence", "confidence"} {
		if f[k] == "" {
			t.Errorf("missing field error %q in %v", k, f)
		}
	}
	if f := fieldsOf(t, func() error {
		_, err := e.svc.Intel.SubmitAssessment(ctx, "mcp:x", service.AssessmentInput{FindingID: fs["a"].ID, Decision: "monitor", Score: 10, Rationale: "too short", Confidence: "low"})
		return err
	}()); !strings.Contains(f["evidence"], "rationale") {
		t.Fatalf("no evidence and a short rationale: %v", f)
	}
	if f := fieldsOf(t, func() error {
		rt := in
		rt.FindingID = fs["rt"].ID
		_, err := e.svc.Intel.SubmitAssessment(ctx, "mcp:x", rt)
		return err
	}()); f["finding_id"] == "" {
		t.Fatalf("runtime finding must be rejected: %v", f)
	}
	missing := in
	missing.FindingID = "nope"
	if _, err := e.svc.Intel.SubmitAssessment(ctx, "mcp:x", missing); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("missing finding: %v", err)
	}

	// One repo-agnostic assessment covers GHSA-1 in every repo.
	a, err := e.svc.Intel.SubmitAssessment(ctx, "mcp:x", in)
	must(t, err)
	if a.ID == 0 || a.Repo != "" || a.AdvisoryID != "GHSA-1" || a.Package != "lodash" || a.Version != "1.0.0" || a.InputsHash == "" ||
		a.AssessedBy != "mcp:x" || !a.AssessedAt.Equal(t0) || a.Decision != model.DecisionSchedule {
		t.Fatalf("assessment %+v", a)
	}
	if got := triageAdvisories(t, e, service.TriageFilter{}); strings.Join(got, ",") != "GHSA-3@o/a" {
		t.Fatalf("assessed item must leave the queue: %v", got)
	}
	// A repo-specific decision for o/c; a substantial rationale stands in for evidence.
	spec, err := e.svc.Intel.SubmitAssessment(ctx, "mcp:x", service.AssessmentInput{FindingID: fs["c"].ID, Decision: "not-affected", Score: 5,
		Rationale: "o/c never calls _.template, the vulnerable function", Confidence: "high", RepoSpecific: true})
	must(t, err)
	if spec.Repo != "o/c" || len(spec.Evidence) != 0 {
		t.Fatalf("repo-specific %+v", spec)
	}

	st, err := e.svc.Intel.LatestAssessments(ctx, []model.Finding{fs["a"], fs["b"], fs["c"], fs["med"], fs["rt"]}, 0)
	must(t, err)
	if len(st) != 3 || st[fs["a"].ID].Assessment.ID != a.ID || st[fs["b"].ID].Assessment.ID != a.ID || !st[fs["a"].ID].Fresh ||
		st[fs["c"].ID].Assessment.ID != spec.ID || !st[fs["c"].ID].Fresh {
		t.Fatalf("latest %+v", st)
	}
	// EPSS moves within its 0.1 bucket: still fresh. KEV listing: stale.
	jitter, listed := fs["a"], fs["a"]
	jitter.EPSS, listed.InKEV, listed.ID = 0.14, true, "listed"
	st, err = e.svc.Intel.LatestAssessments(ctx, []model.Finding{jitter, listed}, 0)
	must(t, err)
	if !st[jitter.ID].Fresh {
		t.Fatal("EPSS jitter inside the bucket must keep the assessment fresh")
	}
	if st["listed"].Assessment.ID != a.ID || st["listed"].Fresh {
		t.Fatal("a finding newly in KEV must make the assessment stale")
	}

	hist, err := e.svc.Intel.Assessments(ctx, fs["c"].ID, 0)
	must(t, err)
	if len(hist) != 2 || hist[0].ID != spec.ID || hist[1].ID != a.ID {
		t.Fatalf("history of o/c %+v", hist)
	}
	if hist, _ := e.svc.Intel.Assessments(ctx, fs["a"].ID, 0); len(hist) != 1 {
		t.Fatalf("history of o/a must not include o/c's assessment: %+v", hist)
	}

	// After staleAfter, the agnostic item returns for o/a and o/b, and o/c's
	// repo-specific assessment comes back as its own item.
	e.now = t0.Add(31 * 24 * time.Hour)
	q, err = e.svc.Intel.TriageQueue(ctx, service.TriageFilter{})
	must(t, err)
	if len(q) != 3 || strings.Join(q[0].Repos, ",") != "o/a,o/b" || q[0].LastAssessment == nil || q[0].LastAssessment.ID != a.ID ||
		!strings.Contains(q[0].Reason, "31 days") || q[1].Finding.ID != fs["c"].ID || q[1].LastAssessment == nil || q[1].LastAssessment.ID != spec.ID {
		t.Fatalf("stale queue %+v", q)
	}
	if q, _ := e.svc.Intel.TriageQueue(ctx, service.TriageFilter{StaleAfter: 60 * 24 * time.Hour}); len(q) != 1 {
		t.Fatalf("stale_after ignored: %+v", q)
	}

	// Assessments never change the finding.
	got, err := e.st.GetFinding(ctx, fs["a"].ID)
	must(t, err)
	if got.Priority != 50 || got.Status != model.StatusOpen || got.Severity != model.SeverityHigh {
		t.Fatalf("finding changed: %+v", got)
	}
	if acts := auditActions(t, e.st); strings.Join(acts, ",") != "agent.assessment.submit,agent.assessment.submit" {
		t.Fatalf("audit %v", acts)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// storeOnly hides every optional capability of the wrapped store.
type storeOnly struct{ store.Store }
