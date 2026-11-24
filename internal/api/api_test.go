package api_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/hungnm98/heimdall-cve/internal/api"
	"github.com/hungnm98/heimdall-cve/internal/jobs/inline"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/notify"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/secret"
	"github.com/hungnm98/heimdall-cve/internal/service"
	"github.com/hungnm98/heimdall-cve/internal/store"
	"github.com/hungnm98/heimdall-cve/internal/store/memstore"
	"github.com/hungnm98/heimdall-cve/internal/vcs"
)

// ---- OpenAPI contract checking ----

var (
	specOnce   sync.Once
	specRouter routers.Router
	specErr    error
)

func router(t *testing.T) routers.Router {
	t.Helper()
	specOnce.Do(func() {
		doc, err := openapi3.NewLoader().LoadFromFile("../../api/openapi.yaml")
		if err != nil {
			specErr = err
			return
		}
		doc.Servers = nil // match paths without the /api/v1 prefix
		specRouter, specErr = gorillamux.NewRouter(doc)
	})
	if specErr != nil {
		t.Fatal(specErr)
	}
	return specRouter
}

// coverage records operationId → statuses seen, to prove every documented
// response was exercised.
type coverage struct {
	mu   sync.Mutex
	seen map[string]map[int]bool
}

var cov = &coverage{seen: map[string]map[int]bool{}}

func (c *coverage) add(op string, status int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen[op] == nil {
		c.seen[op] = map[int]bool{}
	}
	c.seen[op][status] = true
}

type client struct {
	t       *testing.T
	h       http.Handler
	headers map[string]string
}

// do sends a request (writes carry the CSRF headers) and validates the
// response against the spec, including that its status is documented.
func (c *client) do(method, path string, body any) *httptest.ResponseRecorder {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Heimdall-Request", "1")
	}
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	c.validate(req, rec)
	return rec
}

func (c *client) validate(req *http.Request, rec *httptest.ResponseRecorder) {
	c.t.Helper()
	vreq := req.Clone(context.Background())
	vreq.URL.Path = strings.TrimPrefix(req.URL.Path, api.Prefix)
	vreq.RequestURI = ""
	route, params, err := router(c.t).FindRoute(vreq)
	if err != nil {
		c.t.Fatalf("%s %s: not in the spec: %v", req.Method, req.URL.Path, err)
	}
	cov.add(route.Operation.OperationID, rec.Code)
	in := &openapi3filter.RequestValidationInput{Request: vreq, PathParams: params, Route: route}
	out := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: in, Status: rec.Code, Header: rec.Header(),
		Body:    io.NopCloser(bytes.NewReader(rec.Body.Bytes())),
		Options: &openapi3filter.Options{IncludeResponseStatus: true, MultiError: true},
	}
	if err := openapi3filter.ValidateResponse(context.Background(), out); err != nil {
		c.t.Errorf("%s %s → %d does not match the spec: %v\nbody: %s", req.Method, req.URL.Path, rec.Code, err, rec.Body)
	}
}

func (c *client) expect(status int, method, path string, body any) map[string]any {
	c.t.Helper()
	rec := c.do(method, path, body)
	if rec.Code != status {
		c.t.Fatalf("%s %s = %d, want %d: %s", method, path, rec.Code, status, rec.Body)
	}
	var out map[string]any
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return out
}

// ---- fixtures ----

type fakeProvider struct{ err error }

func (p *fakeProvider) Name() string { return "github" }
func (p *fakeProvider) ListRepos(_ context.Context, t model.Target) ([]model.Repo, error) {
	if p.err != nil {
		return nil, p.err
	}
	return []model.Repo{{Provider: "github", Host: "github.com", Owner: t.Owner, Name: "api", Ref: "main", DefaultBranch: "main"}}, nil
}
func (p *fakeProvider) ResolveRef(context.Context, model.Repo, string) (string, error) {
	return "", nil
}
func (p *fakeProvider) ListFiles(context.Context, model.Repo, string) ([]string, error) {
	return nil, nil
}
func (p *fakeProvider) ReadFile(context.Context, model.Repo, string, string) ([]byte, error) {
	return nil, nil
}
func (p *fakeProvider) Checkout(context.Context, model.Repo, string, string) error { return nil }

type fakeNotifier struct {
	name string
	err  error
}

func (n fakeNotifier) Name() string                                          { return n.name }
func (n fakeNotifier) Notify(context.Context, model.NotificationEvent) error { return n.err }

type fixture struct {
	st   *memstore.Store
	prov *fakeProvider
	svc  *service.Services
	h    http.Handler
	c    *client
}

func newFixture(t *testing.T, withKeys bool, opts api.Options) *fixture {
	t.Helper()
	ib, err := inline.New(plugin.Config{}, plugin.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{st: memstore.New(), prov: &fakeProvider{}}
	var keys *secret.KeyRing
	if withKeys {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		keys, _ = secret.NewKeyRing(base64.StdEncoding.EncodeToString(b))
	}
	f.svc = service.New(service.Deps{
		Store: f.st, Jobs: ib, Keys: keys,
		ProviderFor: func(context.Context, model.Target) (vcs.Provider, error) { return f.prov, nil },
		Notifiers:   []notify.Notifier{fakeNotifier{name: "slack"}, fakeNotifier{name: "broken", err: errors.New("webhook 500")}},
		SourceKinds: map[string][]string{"osv": {"vuln-source"}, "kev": {"enricher"}},
	})
	if opts.Version == "" {
		opts.Version = "test"
	}
	f.h = api.NewHandler(f.svc, opts)
	f.c = &client{t: t, h: f.h}
	return f
}

func (f *fixture) seed(t *testing.T) (findingID string, runID int64) {
	t.Helper()
	ctx := context.Background()
	at := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	mk := func() int64 {
		run := &model.ScanRun{StartedAt: at, Targets: []string{"org:acme"}}
		if err := f.st.StartRun(ctx, run); err != nil {
			t.Fatal(err)
		}
		return run.ID
	}
	finish := func(id int64) {
		run, _ := f.st.GetRun(ctx, id)
		run.Status, run.FinishedAt = model.RunPartial, at.Add(time.Minute)
		run.ReposScanned = []string{"acme/api"}
		run.Sources = []model.SourceHealth{{Name: "osv", Healthy: true, Calls: 3, Duration: time.Second}, {Name: "kev", Healthy: false, Error: "timeout"}}
		run.Stats = model.RunStats{OpenBySeverity: map[model.Severity]int{model.SeverityHigh: 1}, New: 1, Repos: 1}
		if err := f.st.FinishRun(ctx, run); err != nil {
			t.Fatal(err)
		}
	}
	r1 := mk()
	finish(r1)
	r2 := mk()
	eol := at.AddDate(0, -1, 0)
	fs := []model.Finding{
		{Kind: model.KindDependency, Provider: "github", Repo: "acme/api", ManifestPath: "go.mod",
			Package: model.NewPackage(model.EcosystemGo, "golang.org/x/net", "v0.1.0"), Direct: true, Scope: model.ScopeProd,
			AdvisoryID: "GO-2024-0001", Aliases: []string{"CVE-2024-0001"}, Severity: model.SeverityHigh, InKEV: true,
			Verified: true, Sources: []string{"osv"}, FixedVersions: []string{"v0.23.0"}, RecommendedVersion: "v0.23.0",
			Bump: model.BumpMinor, Advice: "go get golang.org/x/net@v0.23.0", Priority: 9},
		{Kind: model.KindRuntime, Provider: "github", Repo: "acme/api", ManifestPath: "go.mod", AdvisoryID: "EOL-go-1.20",
			Severity: model.SeverityMedium, Sources: []string{"endoflife"},
			Runtime: &model.RuntimeStatus{Runtime: model.Runtime{Name: "go", Version: "1.20", Origin: "go.mod", Via: "go directive"},
				Cycle: "1.20", Status: model.SupportEOL, EOLDate: &eol, LatestCycle: "1.26"}},
	}
	for i := range fs {
		fs[i].ComputeID()
	}
	if _, err := f.st.RecordFindings(ctx, r2, []string{"acme/api"}, fs, at); err != nil {
		t.Fatal(err)
	}
	finish(r2)
	return fs[0].ID, r2
}

// ---- tests ----

func TestOpenAPIContract(t *testing.T) {
	f := newFixture(t, true, api.Options{TrustedUserHeader: "X-Forwarded-Email", JobsBackend: "inline", Providers: []string{"github"}, AuthTypes: []string{"token", "app", "ssh"}})
	c := f.c
	c.headers = map[string]string{"X-Forwarded-Email": "alice@example.com"}
	ctx := context.Background()
	findingID, runID := f.seed(t)

	meta := c.expect(200, "GET", "/api/v1/meta", nil)
	if meta["secrets_enabled"] != true || meta["jobs_backend"] != "inline" {
		t.Fatal(meta)
	}

	// auth profiles
	p := c.expect(201, "POST", "/api/v1/auth-profiles", map[string]any{"name": "pat", "type": "token", "secret": "ghp_supersecretvalue_1234"})
	if p["has_secret"] != true || p["secret_fingerprint"] == "" || strings.Contains(fmt.Sprint(p), "supersecret") {
		t.Fatalf("profile %v", p)
	}
	if opts, _ := p["options"].(map[string]any); opts["token_ref"] != nil {
		t.Fatal("token_ref must not be exposed")
	}
	c.expect(400, "POST", "/api/v1/auth-profiles", map[string]any{"name": "Bad!", "type": "token"})
	c.expect(409, "POST", "/api/v1/auth-profiles", map[string]any{"name": "pat", "type": "token"})
	c.expect(201, "POST", "/api/v1/auth-profiles", map[string]any{"name": "spare", "type": "ssh", "options": map[string]any{"known_hosts": "~/.ssh/known_hosts"}})
	c.expect(200, "PATCH", "/api/v1/auth-profiles/spare", map[string]any{"name": "spare", "type": "ssh"})
	c.expect(400, "PATCH", "/api/v1/auth-profiles/spare", map[string]any{"name": "spare", "type": "nope"})
	c.expect(404, "PATCH", "/api/v1/auth-profiles/missing", map[string]any{"name": "missing", "type": "token"})
	cfgProfile := &model.AuthProfile{Name: "cfg", Type: "token", Options: map[string]any{"token_env": "GITHUB_TOKEN"}, Origin: model.OriginConfig}
	if err := f.st.SaveAuthProfile(ctx, cfgProfile); err != nil {
		t.Fatal(err)
	}
	c.expect(409, "PATCH", "/api/v1/auth-profiles/cfg", map[string]any{"name": "cfg", "type": "token"})
	c.expect(200, "POST", "/api/v1/auth-profiles/pat/test", nil)
	c.expect(404, "POST", "/api/v1/auth-profiles/missing/test", nil)

	// targets
	in := map[string]any{"kind": "org", "owner": "acme", "auth": "pat", "schedule": "0 2 */3 * *"}
	tg := c.expect(201, "POST", "/api/v1/targets", in)
	if tg["label"] != "org:acme" || tg["enabled"] != true || tg["next_run_at"] == nil || tg["origin"] != "ui" {
		t.Fatalf("target %v", tg)
	}
	tid := int64(tg["id"].(float64))
	c.expect(400, "POST", "/api/v1/targets", map[string]any{"kind": "org", "auth": "pat", "schedule": "bad"})
	rt := c.expect(201, "POST", "/api/v1/targets", map[string]any{"kind": "repo", "url": "git@github.com:acme/web.git", "auth": "pat", "enabled": false})
	if rt["url"] != "https://github.com/acme/web" || rt["name"] != "web" || rt["next_run_at"] != nil {
		t.Fatalf("repo target %v", rt)
	}
	c.expect(200, "GET", "/api/v1/targets", nil)
	c.expect(200, "GET", fmt.Sprintf("/api/v1/targets/%d", tid), nil)
	c.expect(404, "GET", "/api/v1/targets/999", nil)
	c.expect(404, "GET", "/api/v1/targets/abc", nil)
	c.expect(200, "PATCH", fmt.Sprintf("/api/v1/targets/%d", tid), map[string]any{"kind": "org", "owner": "acme", "auth": "pat", "filter": map[string]any{"include": []string{"api-*"}}})
	c.expect(400, "PATCH", fmt.Sprintf("/api/v1/targets/%d", tid), map[string]any{"kind": "org", "auth": "pat"})
	c.expect(404, "PATCH", "/api/v1/targets/999", in)
	cfgTarget := &model.TargetSpec{Target: model.Target{Kind: model.TargetOrg, Provider: "github", Owner: "acme", Auth: "cfg", ListAuth: "cfg"}, Origin: model.OriginConfig, Enabled: true}
	if err := f.st.SaveTarget(ctx, cfgTarget); err != nil {
		t.Fatal(err)
	}
	c.expect(409, "PATCH", fmt.Sprintf("/api/v1/targets/%d", cfgTarget.ID), in)
	c.expect(409, "DELETE", fmt.Sprintf("/api/v1/targets/%d", cfgTarget.ID), nil)
	c.expect(404, "DELETE", "/api/v1/targets/999", nil)
	pv := c.expect(200, "POST", "/api/v1/targets/preview", in)
	if len(pv["items"].([]any)) != 1 {
		t.Fatal(pv)
	}
	c.expect(400, "POST", "/api/v1/targets/preview", map[string]any{"kind": "x", "auth": "pat"})
	f.prov.err = errors.New("bad credentials")
	c.expect(502, "POST", "/api/v1/targets/preview", in)
	f.prov.err = nil

	profiles := c.expect(200, "GET", "/api/v1/auth-profiles", nil)
	for _, it := range profiles["items"].([]any) {
		m := it.(map[string]any)
		if m["name"] == "pat" && len(m["used_by"].([]any)) != 2 {
			t.Fatalf("used_by %v", m)
		}
	}
	c.expect(409, "DELETE", "/api/v1/auth-profiles/pat", nil)
	c.expect(204, "DELETE", fmt.Sprintf("/api/v1/targets/%d", int64(rt["id"].(float64))), nil)
	c.expect(204, "DELETE", "/api/v1/auth-profiles/spare", nil)
	c.expect(404, "DELETE", "/api/v1/auth-profiles/spare", nil)

	// repos
	if err := f.st.UpsertRepos(ctx, tid, []model.Repo{{Provider: "github", Owner: "acme", Name: "api", Ref: "main"}, {Provider: "github", Owner: "acme", Name: "web", Ref: "main"}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	rp := c.expect(200, "GET", "/api/v1/repos?limit=1", nil)
	if rp["next_cursor"] != "acme/api" {
		t.Fatal(rp)
	}
	c.expect(200, "GET", "/api/v1/repos?limit=1&cursor=acme/api&q=acme&target_id="+fmt.Sprint(tid), nil)
	rd := c.expect(200, "GET", "/api/v1/repos/acme/api", nil)
	if len(rd["upgrade_plan"].([]any)) != 1 || len(rd["runtimes"].([]any)) != 1 {
		t.Fatal(rd)
	}
	c.expect(404, "GET", "/api/v1/repos/acme/none", nil)

	// findings
	fl := c.expect(200, "GET", "/api/v1/findings?limit=1&min_severity=MEDIUM&status=open", nil)
	if fl["next_cursor"] == nil {
		t.Fatal(fl)
	}
	c.expect(200, "GET", "/api/v1/findings?cursor="+fl["next_cursor"].(string), nil)
	c.expect(200, "GET", "/api/v1/findings?kev=true&q=CVE-2024-0001&kind=dependency&new_since=2026-01-01T00:00:00Z&repo=acme/api", nil)
	c.expect(400, "GET", "/api/v1/findings?cursor=@@@", nil)
	c.expect(400, "GET", "/api/v1/findings?kev=maybe", nil)
	c.expect(200, "GET", "/api/v1/findings/"+findingID, nil)
	c.expect(404, "GET", "/api/v1/findings/nope", nil)
	exp := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	c.expect(204, "PUT", "/api/v1/findings/"+findingID+"/suppression", map[string]any{"reason": "accepted risk", "expires_at": exp})
	fd := c.expect(200, "GET", "/api/v1/findings/"+findingID, nil)
	if fd["status"] != "suppressed" || fd["suppression"].(map[string]any)["actor"] != "alice@example.com" {
		t.Fatal(fd)
	}
	c.expect(400, "PUT", "/api/v1/findings/"+findingID+"/suppression", map[string]any{"reason": "x", "expires_at": exp})
	c.expect(400, "PUT", "/api/v1/findings/"+findingID+"/suppression", map[string]any{"reason": "accepted"})
	c.expect(404, "PUT", "/api/v1/findings/nope/suppression", map[string]any{"reason": "accepted risk", "expires_at": exp})
	c.expect(204, "DELETE", "/api/v1/findings/"+findingID+"/suppression", nil)
	c.expect(404, "DELETE", "/api/v1/findings/"+findingID+"/suppression", nil)

	// runs
	runs := c.expect(200, "GET", "/api/v1/runs?limit=1", nil)
	if runs["next_cursor"] != fmt.Sprint(runID) {
		t.Fatal(runs)
	}
	c.expect(200, "GET", "/api/v1/runs?cursor="+fmt.Sprint(runID), nil)
	c.expect(200, "GET", fmt.Sprintf("/api/v1/runs/%d", runID), nil)
	c.expect(404, "GET", "/api/v1/runs/999", nil)
	c.expect(200, "GET", fmt.Sprintf("/api/v1/runs/%d/diff", runID), nil)
	c.expect(200, "GET", fmt.Sprintf("/api/v1/runs/%d/diff?against=%d", runID, runID-1), nil)
	c.expect(404, "GET", fmt.Sprintf("/api/v1/runs/%d/diff", runID-1), nil)

	// jobs
	j := c.expect(201, "POST", "/api/v1/jobs", map[string]any{"target_id": tid})
	jid := int64(j["id"].(float64))
	if j["requested_by"] != "alice@example.com" || j["status"] != "queued" {
		t.Fatal(j)
	}
	if again := c.expect(200, "POST", "/api/v1/jobs", map[string]any{"target_id": tid}); int64(again["id"].(float64)) != jid {
		t.Fatal(again)
	}
	c.expect(400, "POST", "/api/v1/jobs", map[string]any{"repo_url": "nope"})
	c.expect(404, "POST", "/api/v1/jobs", map[string]any{"target_id": 999})
	c.expect(201, "POST", "/api/v1/jobs", map[string]any{"repo_url": "https://github.com/acme/x", "auth_profile": "pat", "branch": "dev"})
	c.expect(201, "POST", "/api/v1/jobs", nil) // empty body = every target
	c.expect(200, "GET", "/api/v1/jobs?limit=1&status=queued&target_id="+fmt.Sprint(tid), nil)
	jl := c.expect(200, "GET", "/api/v1/jobs?limit=1", nil)
	c.expect(200, "GET", "/api/v1/jobs?cursor="+jl["next_cursor"].(string), nil)
	c.expect(200, "GET", fmt.Sprintf("/api/v1/jobs/%d", jid), nil)
	c.expect(404, "GET", "/api/v1/jobs/999", nil)
	c.expect(202, "POST", fmt.Sprintf("/api/v1/jobs/%d/cancel", jid), nil)
	c.expect(409, "POST", fmt.Sprintf("/api/v1/jobs/%d/cancel", jid), nil)
	c.expect(404, "POST", "/api/v1/jobs/999/cancel", nil)
	ev := c.expect(200, "GET", fmt.Sprintf("/api/v1/jobs/%d/events?after_id=0&limit=10", jid), nil)
	if len(ev["items"].([]any)) != 1 {
		t.Fatal(ev)
	}
	c.expect(404, "GET", "/api/v1/jobs/999/events", nil)

	// dashboard
	d := c.expect(200, "GET", "/api/v1/dashboard?trend_runs=5", nil)
	if d["open_kev"] != float64(1) || len(d["eol_runtimes"].([]any)) != 1 || len(d["unhealthy_sources"].([]any)) != 1 || d["repos"] != float64(2) {
		t.Fatal(d)
	}

	// system
	src := c.expect(200, "GET", "/api/v1/sources", nil)
	if len(src["items"].([]any)) != 2 {
		t.Fatal(src)
	}
	c.expect(200, "GET", "/api/v1/notifiers", nil)
	c.expect(204, "POST", "/api/v1/notifiers/slack/test", nil)
	c.expect(502, "POST", "/api/v1/notifiers/broken/test", nil)
	c.expect(404, "POST", "/api/v1/notifiers/none/test", nil)
	au := c.expect(200, "GET", "/api/v1/audit?limit=2", nil)
	if au["next_cursor"] == nil || au["items"].([]any)[0].(map[string]any)["actor"] != "alice@example.com" {
		t.Fatal(au)
	}
	c.expect(200, "GET", "/api/v1/audit?cursor="+au["next_cursor"].(string), nil)

	// secrets disabled → 503
	f2 := newFixture(t, false, api.Options{})
	if m := f2.c.expect(200, "GET", "/api/v1/meta", nil); m["secrets_enabled"] != false {
		t.Fatal(m)
	}
	f2.c.expect(503, "POST", "/api/v1/auth-profiles", map[string]any{"name": "pat", "type": "token", "secret": "x-secret"})

	checkCoverage(t)
}

// checkCoverage fails for any documented (operation, status) never exercised,
// except responses the service cannot produce through valid input.
func checkCoverage(t *testing.T) {
	t.Helper()
	unreachable := map[string]bool{
		"createTarget 409": true, // unknown auth profile is a 400 (validated) before the store's 409
	}
	doc, err := openapi3.NewLoader().LoadFromFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var missing []string
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			for code := range op.Responses.Map() {
				var status int
				fmt.Sscan(code, &status)
				key := op.OperationID + " " + code
				if !cov.seen[op.OperationID][status] && !unreachable[key] {
					missing = append(missing, fmt.Sprintf("%s %s %s (%s)", method, path, code, op.OperationID))
				}
			}
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("documented responses not exercised:\n%s", strings.Join(missing, "\n"))
	}
}

func TestCSRFGuard(t *testing.T) {
	f := newFixture(t, false, api.Options{})
	cases := []struct {
		name    string
		headers map[string]string
	}{
		{"no headers", nil},
		{"no X-Heimdall-Request", map[string]string{"Content-Type": "application/json"}},
		{"form content type", map[string]string{"Content-Type": "application/x-www-form-urlencoded", "X-Heimdall-Request": "1"}},
		{"wrong marker", map[string]string{"Content-Type": "application/json", "X-Heimdall-Request": "yes"}},
	}
	for _, tc := range cases {
		req := httptest.NewRequest("POST", "/api/v1/jobs", strings.NewReader(`{}`))
		for k, v := range tc.headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		f.h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden || rec.Header().Get("Content-Type") != "application/problem+json" {
			t.Errorf("%s: %d %s", tc.name, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
	if jobs, _ := f.st.ListJobs(context.Background(), store.JobFilter{}); len(jobs) != 0 {
		t.Fatal("a rejected write must not create a job")
	}
	req := httptest.NewRequest("POST", "/api/v1/jobs", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("X-Heimdall-Request", "1")
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("valid write: %d %s", rec.Code, rec.Body)
	}
}

func TestProblemDetailsAndLimits(t *testing.T) {
	f := newFixture(t, false, api.Options{})
	rec := f.c.do("POST", "/api/v1/targets", map[string]any{"kind": "nope"})
	var p struct {
		Type, Title, Detail string
		Status              int
		Fields              map[string]string
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if rec.Header().Get("Content-Type") != "application/problem+json" || p.Status != 400 || p.Fields["kind"] == "" || p.Fields["auth"] == "" {
		t.Fatalf("%+v", p)
	}

	req := httptest.NewRequest("POST", "/api/v1/targets", strings.NewReader(`{"kind":`+strings.Repeat(" ", api.MaxBodyBytes)+`"org"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Heimdall-Request", "1")
	rec = httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large body: %d", rec.Code)
	}

	req = httptest.NewRequest("POST", "/api/v1/targets", strings.NewReader(`{bad json`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Heimdall-Request", "1")
	rec = httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad json: %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	f.h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/nothing", nil))
	if rec.Code != http.StatusNotFound || rec.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("unknown endpoint: %d", rec.Code)
	}
}

type panicDashboard struct{}

func (panicDashboard) Summary(context.Context, int) (*service.DashboardSummary, error) {
	panic("boom: internal detail")
}

type failingDashboard struct{}

func (failingDashboard) Summary(context.Context, int) (*service.DashboardSummary, error) {
	return nil, errors.New("pq: password authentication failed for user heimdall")
}

func TestRecoveryAndInternalErrors(t *testing.T) {
	for name, d := range map[string]service.Dashboard{"panic": panicDashboard{}, "error": failingDashboard{}} {
		h := api.NewHandler(&service.Services{Dashboard: d}, api.Options{})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/dashboard", nil))
		body := rec.Body.String()
		if rec.Code != 500 || rec.Header().Get("Content-Type") != "application/problem+json" ||
			strings.Contains(body, "boom") || strings.Contains(body, "password") {
			t.Errorf("%s: %d %s", name, rec.Code, body)
		}
		if !strings.Contains(body, rec.Header().Get("X-Request-ID")) {
			t.Errorf("%s: problem should reference the request id", name)
		}
	}
}

func TestSecurityHeadersAndHealth(t *testing.T) {
	fallback := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "spa") })
	f := newFixture(t, false, api.Options{Fallback: fallback})
	for _, path := range []string{"/api/v1/meta", "/healthz", "/readyz", "/some/page"} {
		rec := httptest.NewRecorder()
		f.h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 {
			t.Errorf("%s: %d", path, rec.Code)
		}
		h := rec.Header()
		if !strings.Contains(h.Get("Content-Security-Policy"), "default-src 'self'") || h.Get("X-Frame-Options") != "DENY" ||
			h.Get("Referrer-Policy") != "no-referrer" || h.Get("X-Content-Type-Options") != "nosniff" || h.Get("X-Request-ID") == "" {
			t.Errorf("%s: headers %v", path, h)
		}
	}
}

func TestJobEventsSSE(t *testing.T) {
	f := newFixture(t, false, api.Options{EventPoll: 10 * time.Millisecond, Heartbeat: 20 * time.Millisecond})
	srv := httptest.NewServer(f.h)
	defer srv.Close()
	ctx := context.Background()
	j, _, err := f.svc.Jobs.Trigger(ctx, "a", service.JobRequest{})
	if err != nil {
		t.Fatal(err)
	}
	add := func(msg string) int64 {
		e := &model.JobEvent{JobID: j.ID, Level: "info", Message: msg}
		if err := f.st.AppendJobEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
		return e.ID
	}
	first := add("listing repos")
	add("scanning acme/api")

	open := func(lastID int64) (*http.Response, *bufio.Reader) {
		req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/jobs/%d/events", srv.URL, j.ID), nil)
		req.Header.Set("Accept", "text/event-stream")
		if lastID > 0 {
			req.Header.Set("Last-Event-ID", fmt.Sprint(lastID))
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
			t.Fatalf("status %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		return resp, bufio.NewReader(resp.Body)
	}
	// readEvent returns the next event (skipping heartbeat comments).
	readEvent := func(br *bufio.Reader) (name, id, data string, heartbeats int) {
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				t.Fatalf("stream ended: %v", err)
			}
			line = strings.TrimRight(line, "\n")
			switch {
			case strings.HasPrefix(line, ":"):
				heartbeats++
			case strings.HasPrefix(line, "event: "):
				name = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "id: "):
				id = strings.TrimPrefix(line, "id: ")
			case strings.HasPrefix(line, "data: "):
				data = strings.TrimPrefix(line, "data: ")
			case line == "" && name != "":
				return name, id, data, heartbeats
			}
		}
	}

	resp, br := open(0)
	if name, id, data, _ := readEvent(br); name != "progress" || id != fmt.Sprint(first) || !strings.Contains(data, "listing repos") {
		t.Fatalf("first event %s %s %s", name, id, data)
	}
	readEvent(br)
	// Live event, after a heartbeat.
	time.Sleep(50 * time.Millisecond)
	add("found 3 findings")
	name, _, data, hb := readEvent(br)
	if name != "progress" || !strings.Contains(data, "found 3 findings") || hb == 0 {
		t.Fatalf("live event %s %s heartbeats=%d", name, data, hb)
	}
	// Finish the job: stream sends done and closes.
	job, _ := f.st.GetJob(ctx, j.ID)
	now := time.Now()
	job.Status, job.FinishedAt = model.JobSucceeded, &now
	_ = f.st.UpdateJob(ctx, job)
	name, _, data, _ = readEvent(br)
	if name != "done" || !strings.Contains(data, `"status":"succeeded"`) {
		t.Fatalf("done event %s %s", name, data)
	}
	if _, err := br.ReadString('\n'); err != io.EOF {
		t.Fatalf("stream should close after done: %v", err)
	}
	resp.Body.Close()

	// Resume after the first event: replays the rest, then done.
	resp, br = open(first)
	defer resp.Body.Close()
	if _, _, data, _ := readEvent(br); !strings.Contains(data, "scanning acme/api") {
		t.Fatalf("resume %s", data)
	}
	readEvent(br)
	if name, _, _, _ := readEvent(br); name != "done" {
		t.Fatal(name)
	}

	// Unknown job: a problem, not a stream.
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/jobs/999/events", nil)
	req.Header.Set("Accept", "text/event-stream")
	r404, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r404.Body.Close()
	if r404.StatusCode != 404 {
		t.Fatal(r404.StatusCode)
	}
}

func TestSSEStopsOnDisconnect(t *testing.T) {
	done := make(chan struct{})
	f := newFixture(t, false, api.Options{EventPoll: 5 * time.Millisecond, Done: done})
	j, _, _ := f.svc.Jobs.Trigger(context.Background(), "a", service.JobRequest{})
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/jobs/%d/events", j.ID), nil).WithContext(ctx)
	req.Header.Set("Accept", "text/event-stream")
	finished := make(chan struct{})
	go func() {
		f.h.ServeHTTP(httptest.NewRecorder(), req)
		close(finished)
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not stop on client disconnect")
	}

	req = httptest.NewRequest("GET", fmt.Sprintf("/api/v1/jobs/%d/events", j.ID), nil)
	req.Header.Set("Accept", "text/event-stream")
	finished = make(chan struct{})
	go func() {
		f.h.ServeHTTP(httptest.NewRecorder(), req)
		close(finished)
	}()
	time.Sleep(30 * time.Millisecond)
	close(done)
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not stop on shutdown")
	}
}
