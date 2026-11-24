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

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// storeOnly hides every optional capability of the wrapped store.
type storeOnly struct{ store.Store }
