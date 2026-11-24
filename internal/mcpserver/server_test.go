package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hungnm98/heimdall-cve/internal/config"
	"github.com/hungnm98/heimdall-cve/internal/jobs/inline"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/notify"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/service"
	"github.com/hungnm98/heimdall-cve/internal/store/memstore"
)

var t0 = time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)

type fakeNotifier struct {
	mu  sync.Mutex
	evs []model.NotificationEvent
}

func (f *fakeNotifier) Name() string { return "fake" }
func (f *fakeNotifier) Notify(_ context.Context, ev model.NotificationEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.evs = append(f.evs, ev)
	return nil
}

type env struct {
	st       *memstore.Store
	notif    *fakeNotifier
	cs       *mcp.ClientSession
	targetID int64
	runs     [2]int64
	findings []model.Finding
}

// newEnv seeds a memstore with a target, repos, two runs, findings and an
// inventory, and connects an in-memory MCP client named "test-agent".
func newEnv(t *testing.T, enabled bool) *env {
	t.Helper()
	ctx := context.Background()
	e := &env{st: memstore.New(), notif: &fakeNotifier{}}
	cfg := &config.Config{}
	cfg.Store.Type = "memory"
	cfg.MCP = config.MCPConfig{AllowAgentWrites: enabled, AllowNotify: enabled, AllowScan: enabled, NotifyDailyLimit: 5}
	cfg.AuthProfiles = map[string]config.Plugin{"pat": {Type: "token", Options: plugin.Config{"token_env": "SUPER_SECRET_TOKEN_ENV"}}}
	jobsBackend, err := inline.New(plugin.Config{}, plugin.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = jobsBackend.Close() })
	svcs := service.New(service.Deps{
		Config: cfg, Store: e.st, Jobs: jobsBackend, Notifiers: []notify.Notifier{e.notif},
		SourceKinds: map[string][]string{"osv": {"vuln-source"}},
		Now:         func() time.Time { return t0 },
	})
	if _, err := svcs.AuthProfiles.Create(ctx, "seed", service.AuthProfileInput{Name: "pat", Type: "token"}); err != nil {
		t.Fatal(err)
	}
	tg, err := svcs.Targets.Create(ctx, "seed", service.TargetInput{Kind: model.TargetOrg, Owner: "acme", Auth: "pat", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	e.targetID = tg.ID
	if err := e.st.UpsertRepos(ctx, tg.ID, []model.Repo{
		{Provider: "github", Host: "github.com", Owner: "acme", Name: "api", DefaultBranch: "main"},
		{Provider: "github", Host: "github.com", Owner: "acme", Name: "web", DefaultBranch: "main"},
	}, t0); err != nil {
		t.Fatal(err)
	}

	mk := func(name, adv string, sev model.Severity) model.Finding {
		f := model.Finding{Kind: model.KindDependency, Provider: "github", Repo: "acme/web", ManifestPath: "package.json",
			Package: model.NewPackage(model.EcosystemNPM, name, "1.0.0"), Direct: true, AdvisoryID: adv, Severity: sev,
			Verified: true, Sources: []string{"osv"}, RecommendedVersion: "1.0.1", Bump: model.BumpPatch, FixedVersions: []string{"1.0.1"}}
		f.ComputeID()
		return f
	}
	old := mk("lodash", "GHSA-old", model.SeverityMedium)
	crit := mk("left-pad", "GHSA-crit", model.SeverityCritical)
	crit.InKEV = true
	rt := model.Finding{Kind: model.KindRuntime, Provider: "github", Repo: "acme/web", ManifestPath: ".nvmrc", AdvisoryID: "EOL-node-16",
		Severity: model.SeverityHigh, Runtime: &model.RuntimeStatus{Runtime: model.Runtime{Name: "node", Version: "16"}, Cycle: "16", Status: model.SupportEOL}}
	rt.ComputeID()
	for i, fs := range [][]model.Finding{{old}, {old, crit, rt}} {
		run := &model.ScanRun{StartedAt: t0.Add(time.Duration(i) * time.Hour), Targets: []string{"org:acme"}}
		if err := e.st.StartRun(ctx, run); err != nil {
			t.Fatal(err)
		}
		if _, err := e.st.RecordFindings(ctx, run.ID, []string{"acme/web"}, fs, run.StartedAt); err != nil {
			t.Fatal(err)
		}
		run.Status, run.FinishedAt, run.ReposScanned = model.RunSucceeded, run.StartedAt.Add(time.Minute), []string{"acme/web"}
		run.Sources = []model.SourceHealth{{Name: "osv", Healthy: true}}
		if err := e.st.FinishRun(ctx, run); err != nil {
			t.Fatal(err)
		}
		e.runs[i] = run.ID
	}
	e.findings = []model.Finding{old, crit, rt}
	if err := e.st.ReplaceInventory(ctx, "acme/web", []model.InventoryItem{
		{ManifestPath: "package.json", Package: model.NewPackage(model.EcosystemNPM, "left-pad", "1.0.0"), Direct: true},
		{ManifestPath: "package.json", Package: model.NewPackage(model.EcosystemNPM, "lodash", "1.0.0"), Direct: true},
		{ManifestPath: "package.json", Package: model.NewPackage(model.EcosystemNPM, "@acme/secret-ui", "1.0.0"), Direct: true, Private: true},
	}, t0); err != nil {
		t.Fatal(err)
	}

	srv := New(svcs, Options{AllowScan: cfg.MCP.AllowScan, Config: cfg, Audit: e.st, Version: "test", Now: func() time.Time { return t0 }})
	st, ct := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "test-agent", Version: "1"}, nil)
	e.cs, err = client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.cs.Close() })
	return e
}

// call runs a tool and returns its JSON object output, or the error text.
func (e *env) call(t *testing.T, name string, args map[string]any) (map[string]any, string) {
	t.Helper()
	res, err := e.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error %v", name, err)
	}
	text := ""
	if len(res.Content) > 0 {
		if tc, ok := res.Content[0].(*mcp.TextContent); ok {
			text = tc.Text
		}
	}
	if res.IsError {
		return nil, text
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("%s: output is not a JSON object: %q", name, text)
	}
	return out, ""
}

func (e *env) ok(t *testing.T, name string, args map[string]any) map[string]any {
	t.Helper()
	out, errText := e.call(t, name, args)
	if errText != "" {
		t.Fatalf("%s(%v): %s", name, args, errText)
	}
	return out
}

func list(t *testing.T, out map[string]any, key string) []any {
	t.Helper()
	v, ok := out[key].([]any)
	if !ok {
		t.Fatalf("%q is not a list in %v", key, out)
	}
	return v
}

var allTools = []string{
	"list_targets", "list_repos", "get_inventory", "get_analysis_queue", "get_analyses", "get_findings", "get_finding",
	"get_upgrade_plan", "get_runtime_status", "list_runs", "diff_scans", "list_sources", "triage_queue", "get_assessments",
	"scan_target", "scan_repo", "get_scan_status", "submit_advisory", "submit_analysis", "submit_assessment", "notify_user",
}

func TestToolsListed(t *testing.T) {
	e := newEnv(t, false)
	res, err := e.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, tool := range res.Tools {
		got[tool.Name] = true
		if tool.Description == "" || tool.InputSchema == nil {
			t.Errorf("tool %s lacks description or schema", tool.Name)
		}
	}
	for _, n := range allTools {
		if !got[n] {
			t.Errorf("tool %s not listed (write tools are listed even when disabled)", n)
		}
	}
	if len(res.Tools) != len(allTools) {
		t.Errorf("%d tools listed, want %d", len(res.Tools), len(allTools))
	}
}

func TestReadTools(t *testing.T) {
	e := newEnv(t, false)
	if ts := list(t, e.ok(t, "list_targets", nil), "targets"); len(ts) != 1 || ts[0].(map[string]any)["auth_profile"] != "pat" {
		t.Fatalf("targets %v", ts)
	}
	repos := e.ok(t, "list_repos", map[string]any{"limit": 1})
	if len(list(t, repos, "repos")) != 1 || repos["next_cursor"] == "" {
		t.Fatalf("repos page %v", repos)
	}
	repos = e.ok(t, "list_repos", map[string]any{"cursor": repos["next_cursor"]})
	if r := list(t, repos, "repos"); len(r) != 1 || r[0].(map[string]any)["full_name"] != "acme/web" {
		t.Fatalf("second page %v", repos)
	}

	inv := e.ok(t, "get_inventory", map[string]any{"repo": "acme/web"})
	if len(list(t, inv, "items")) != 3 {
		t.Fatalf("inventory %v", inv)
	}
	q := list(t, e.ok(t, "get_analysis_queue", map[string]any{"limit": 5}), "libraries")
	if len(q) != 2 || q[0].(map[string]any)["name"] != "left-pad" {
		t.Fatalf("queue %v (left-pad has a CRITICAL finding; the private package must be absent)", q)
	}
	if a := list(t, e.ok(t, "get_analyses", map[string]any{"ecosystem": "npm", "name": "left-pad"}), "analyses"); len(a) != 0 {
		t.Fatalf("analyses %v", a)
	}

	fs := e.ok(t, "get_findings", map[string]any{"severity": "high"})
	items := list(t, fs, "findings")
	if len(items) != 2 || items[0].(map[string]any)["severity"] != "CRITICAL" || items[0].(map[string]any)["kev"] != true {
		t.Fatalf("findings %v", items)
	}
	if items := list(t, e.ok(t, "get_findings", map[string]any{"kev": true, "kind": "dependency"}), "findings"); len(items) != 1 {
		t.Fatalf("kev findings %v", items)
	}
	page := e.ok(t, "get_findings", map[string]any{"limit": 1})
	if page["next_cursor"] == "" {
		t.Fatalf("expected a next page: %v", page)
	}
	if items := list(t, e.ok(t, "get_findings", map[string]any{"sort": "name", "order": "desc"}), "findings"); len(items) == 0 {
		t.Fatal("get_findings sorted by name returned nothing")
	}
	if _, errText := e.call(t, "get_findings", map[string]any{"sort": "cvss"}); !strings.Contains(errText, "sort") {
		t.Fatalf("bad sort: %s", errText)
	}
	if _, errText := e.call(t, "get_findings", map[string]any{"status": "gone"}); !strings.Contains(errText, "status") {
		t.Fatalf("bad status error %q", errText)
	}

	f := e.ok(t, "get_finding", map[string]any{"id": e.findings[1].ID})
	if f["advisory_id"] != "GHSA-crit" || f["recommended_version"] != "1.0.1" {
		t.Fatalf("finding %v", f)
	}
	if _, errText := e.call(t, "get_finding", map[string]any{"id": "nope"}); !strings.Contains(errText, "not found") {
		t.Fatalf("missing finding error %q", errText)
	}
	plan := e.ok(t, "get_upgrade_plan", map[string]any{"repo": "acme/web"})
	if len(list(t, plan, "upgrades")) == 0 {
		t.Fatalf("plan %v", plan)
	}
	rts := list(t, e.ok(t, "get_runtime_status", nil), "runtimes")
	if len(rts) != 1 || rts[0].(map[string]any)["status"] != "eol" {
		t.Fatalf("runtimes %v", rts)
	}
	runs := list(t, e.ok(t, "list_runs", nil), "runs")
	if len(runs) != 2 {
		t.Fatalf("runs %v", runs)
	}
	d := e.ok(t, "diff_scans", map[string]any{"run_id": e.runs[1]})
	if d["new_count"] != float64(2) || d["still_open_count"] != float64(1) || list(t, d, "new")[0].(map[string]any)["severity"] != "CRITICAL" {
		t.Fatalf("diff %v", d)
	}
	if src := list(t, e.ok(t, "list_sources", nil), "sources"); len(src) != 1 {
		t.Fatalf("sources %v", src)
	}
}

func TestDisabledTools(t *testing.T) {
	e := newEnv(t, false)
	cases := map[string]struct {
		args map[string]any
		flag string
	}{
		"scan_target": {map[string]any{"target_id": e.targetID}, "--allow-scan"},
		"scan_repo":   {map[string]any{"repo_url": "https://github.com/acme/api", "auth_profile": "pat"}, "--allow-scan"},
		"submit_advisory": {map[string]any{"osv_json": testOSV, "evidence": []string{"https://example.com/x"}, "confidence": "high"},
			"--allow-agent-writes"},
		"submit_analysis": {map[string]any{"ecosystem": "npm", "name": "lodash", "verdict": "ok", "summary": "nothing notable found",
			"evidence": []string{"https://example.com/x"}, "confidence": "low"}, "--allow-agent-writes"},
		"submit_assessment": {map[string]any{"finding_id": e.findings[1].ID, "decision": "fix-now", "score": 90,
			"evidence": []string{"https://example.com/x"}, "confidence": "high"}, "--allow-agent-writes"},
		"notify_user": {map[string]any{"title": "t", "body": "b", "severity": "LOW"}, "--allow-notify"},
	}
	for tool, c := range cases {
		_, errText := e.call(t, tool, c.args)
		if !strings.Contains(errText, "disabled") || !strings.Contains(errText, c.flag) {
			t.Errorf("%s: error %q must say it is disabled and name %s", tool, errText, c.flag)
		}
	}
	if len(e.notif.evs) != 0 {
		t.Fatal("nothing may be sent while notify is disabled")
	}
	// get_scan_status is always allowed.
	if _, errText := e.call(t, "get_scan_status", map[string]any{"job_id": 999}); !strings.Contains(errText, "not found") {
		t.Fatalf("get_scan_status: %q", errText)
	}
}

const testOSV = `{"summary": "left-pad 1.0.0 exfiltrates env vars", "aliases": ["CVE-2026-9999"],
 "affected": [{"package": {"ecosystem": "npm", "name": "left-pad"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]}],
 "database_specific": {"severity": "HIGH"}}`

func TestWriteTools(t *testing.T) {
	e := newEnv(t, true)
	adv := e.ok(t, "submit_advisory", map[string]any{"osv_json": testOSV, "evidence": []string{"https://example.com/report"}, "confidence": "medium"})
	if adv["id"] != "HEIMDALL-AGENT-2026-0001" || adv["verified"] != false || adv["source"] != "agent" {
		t.Fatalf("advisory %v", adv)
	}
	// An object is accepted as well as a string.
	var obj map[string]any
	_ = json.Unmarshal([]byte(testOSV), &obj)
	obj["id"] = "GHSA-aaaa-bbbb-cccc"
	if _, errText := e.call(t, "submit_advisory", map[string]any{"osv_json": obj, "evidence": []string{"https://example.com/report"}, "confidence": "medium"}); !strings.Contains(errText, "aliases") {
		t.Fatalf("public id must be rejected with a hint: %q", errText)
	}
	an := e.ok(t, "submit_analysis", map[string]any{"ecosystem": "npm", "name": "left-pad", "version": "1.0.0", "verdict": "malicious",
		"summary": "1.0.0 tarball differs from the tagged source", "evidence": []string{"https://example.com/diff"}, "confidence": "high"})
	if an["agent"] != "mcp:test-agent" || an["verdict"] != "malicious" {
		t.Fatalf("analysis %v", an)
	}
	if a := list(t, e.ok(t, "get_analyses", map[string]any{"ecosystem": "npm", "name": "left-pad"}), "analyses"); len(a) != 1 {
		t.Fatalf("history %v", a)
	}
	n := e.ok(t, "notify_user", map[string]any{"title": "left-pad is malicious", "body": "Remove it.", "severity": "CRITICAL",
		"refs": []string{e.findings[1].ID, "https://example.com/diff"}})
	if n["sent"] != true || len(e.notif.evs) != 1 || len(e.notif.evs[0].Findings) != 1 {
		t.Fatalf("notify %v, events %+v", n, e.notif.evs)
	}
	if n := e.ok(t, "notify_user", map[string]any{"title": "left-pad is malicious", "body": "Remove it.", "severity": "CRITICAL",
		"refs": []string{e.findings[1].ID, "https://example.com/diff"}}); n["sent"] != false {
		t.Fatalf("duplicate %v", n)
	}

	job := e.ok(t, "scan_target", map[string]any{"target_id": e.targetID})
	jobID := job["job"].(map[string]any)["job_id"]
	if job["created"] != true {
		t.Fatalf("scan_target %v", job)
	}
	st := e.ok(t, "get_scan_status", map[string]any{"job_id": jobID})
	if st["status"] != "queued" {
		t.Fatalf("status %v", st)
	}
	if again := e.ok(t, "scan_target", map[string]any{"target_id": e.targetID}); again["created"] != false {
		t.Fatalf("second trigger must return the active job: %v", again)
	}
	if _, errText := e.call(t, "scan_repo", map[string]any{"repo_url": "https://github.com/acme/api", "auth_profile": "nope"}); !strings.Contains(errText, "auth_profile") {
		t.Fatalf("scan_repo validation %q", errText)
	}

	// Every call is audited with the client name; service writes add their own entries.
	entries, err := e.st.ListAudit(context.Background(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]int{}
	for _, en := range entries {
		actions[en.Action]++
		if en.Action == "mcp.call" && en.Actor != "mcp:test-agent" {
			t.Errorf("actor %q", en.Actor)
		}
	}
	if actions["mcp.call"] != 10 || actions["agent.advisory.submit"] != 1 || actions["agent.analysis.submit"] != 1 || actions["agent.notify"] != 2 || actions["job.trigger"] != 1 {
		t.Fatalf("audit actions %v", actions)
	}
}

func TestTriageTools(t *testing.T) {
	e := newEnv(t, true)
	crit := e.findings[1].ID
	// The CRITICAL KEV finding is queued; MEDIUM and runtime findings are not.
	items := list(t, e.ok(t, "triage_queue", nil), "items")
	if len(items) != 1 {
		t.Fatalf("triage queue %v", items)
	}
	it := items[0].(map[string]any)
	if it["finding"].(map[string]any)["id"] != crit || it["repo_count"] != float64(1) || !strings.Contains(it["reason"].(string), "never assessed") {
		t.Fatalf("triage item %v", it)
	}
	if _, errText := e.call(t, "triage_queue", map[string]any{"min_severity": "bogus"}); !strings.Contains(errText, "min_severity") {
		t.Fatalf("bad severity error %q", errText)
	}
	if _, errText := e.call(t, "submit_assessment", map[string]any{"finding_id": crit, "decision": "maybe", "score": 150, "confidence": "high"}); !strings.Contains(errText, "decision") || !strings.Contains(errText, "score") {
		t.Fatalf("validation error %q", errText)
	}

	a := e.ok(t, "submit_assessment", map[string]any{"finding_id": crit, "decision": "fix-now", "score": 95,
		"rationale": "exploited in the wild, patch release available", "evidence": []string{"https://example.com/kev"}, "confidence": "high"})
	if a["decision"] != "fix-now" || a["assessed_by"] != "mcp:test-agent" || a["repo"] != nil || a["package"].(map[string]any)["name"] != "left-pad" {
		t.Fatalf("assessment %v", a)
	}
	if items := list(t, e.ok(t, "triage_queue", nil), "items"); len(items) != 0 {
		t.Fatalf("an assessed finding must leave the queue: %v", items)
	}
	f := e.ok(t, "get_finding", map[string]any{"id": crit})
	brief, ok := f["agent_assessment"].(map[string]any)
	if !ok || brief["decision"] != "fix-now" || brief["score"] != float64(95) || brief["fresh"] != true || f["status"] != "open" {
		t.Fatalf("get_finding must carry the assessment: %v", f)
	}
	fs := list(t, e.ok(t, "get_findings", map[string]any{"kind": "dependency"}), "findings")
	for _, x := range fs {
		x := x.(map[string]any)
		if _, has := x["agent_assessment"]; has != (x["id"] == crit) {
			t.Fatalf("get_findings: only the assessed finding has agent_assessment: %v", fs)
		}
	}
	if h := list(t, e.ok(t, "get_assessments", map[string]any{"finding_id": crit}), "assessments"); len(h) != 1 {
		t.Fatalf("assessments %v", h)
	}
	if _, errText := e.call(t, "get_assessments", map[string]any{"finding_id": "nope"}); !strings.Contains(errText, "not found") {
		t.Fatalf("missing finding error %q", errText)
	}
}

func TestPromptsAndResources(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	ps, err := e.cs.ListPrompts(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, p := range ps.Prompts {
		names[p.Name] = true
	}
	for _, n := range []string{"daily-scan", "analyze-library", "refresh-intel", "triage-findings"} {
		if !names[n] {
			t.Fatalf("prompt %s missing: %v", n, names)
		}
		p, err := e.cs.GetPrompt(ctx, &mcp.GetPromptParams{Name: n})
		if err != nil || len(p.Messages) != 1 {
			t.Fatalf("get prompt %s: %v %v", n, p, err)
		}
		if text := p.Messages[0].Content.(*mcp.TextContent).Text; !strings.Contains(text, "Never suppress findings") && !strings.Contains(text, "never suppress findings") {
			t.Errorf("prompt %s lacks the safety rules", n)
		}
	}

	r, err := e.cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "heimdall://runs/latest"})
	if err != nil {
		t.Fatal(err)
	}
	var latest struct {
		Run struct {
			ID     int64  `json:"id"`
			Status string `json:"status"`
		} `json:"run"`
	}
	if err := json.Unmarshal([]byte(r.Contents[0].Text), &latest); err != nil || latest.Run.ID != e.runs[1] {
		t.Fatalf("latest run %s %v", r.Contents[0].Text, err)
	}
	r, err = e.cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "heimdall://config"})
	if err != nil {
		t.Fatal(err)
	}
	cfgText := r.Contents[0].Text
	if strings.Contains(cfgText, "SUPER_SECRET_TOKEN_ENV") || !strings.Contains(cfgText, "token_env") || !strings.Contains(cfgText, "allow_agent_writes false") {
		t.Fatalf("config resource must list option keys only and the MCP flags:\n%s", cfgText)
	}
}
