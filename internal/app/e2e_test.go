package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/config"
	"github.com/hungnm98/heimdall-cve/internal/core"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

// fakeGitHub serves an org with two repos through the REST endpoints the
// github provider uses. Files can change between scans (new commit SHA).
type fakeGitHub struct {
	mu       sync.Mutex
	files    map[string]map[string]string // repo → path → content
	sha      map[string]string
	contents atomic.Int32 // contents API calls (to prove the SHA cache works)
}

func (g *fakeGitHub) set(repo, sha string, files map[string]string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.files[repo], g.sha[repo] = files, sha
}

func (g *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer test-token" {
		http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case len(parts) == 3 && parts[0] == "orgs" && parts[2] == "repos":
		var out []map[string]any
		names := make([]string, 0, len(g.files))
		for name := range g.files {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			out = append(out, map[string]any{
				"name": name, "owner": map[string]string{"login": "acme"}, "default_branch": "main", "size": 10,
				"html_url": "https://github.com/acme/" + name, "clone_url": "https://github.com/acme/" + name + ".git",
			})
		}
		_ = json.NewEncoder(w).Encode(out)
	case len(parts) >= 5 && parts[0] == "repos" && parts[3] == "commits":
		_, _ = io.WriteString(w, g.sha[parts[2]])
	case len(parts) >= 6 && parts[0] == "repos" && parts[3] == "git" && parts[4] == "trees":
		var tree []map[string]string
		for p := range g.files[parts[2]] {
			tree = append(tree, map[string]string{"path": p, "type": "blob"})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"tree": tree, "truncated": false})
	case len(parts) >= 5 && parts[0] == "repos" && parts[3] == "contents":
		g.contents.Add(1)
		path := strings.Join(parts[4:], "/")
		c, ok := g.files[parts[2]][path]
		if !ok || r.URL.Query().Get("ref") != g.sha[parts[2]] {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, c)
	default:
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
	}
}

// fakeOSV serves the recorded OSV records under source/osv/testdata/vulns:
// querybatch returns every record naming the queried package (like OSV, but
// without version filtering: the pipeline re-evaluates ranges itself).
func fakeOSV(t *testing.T) http.Handler {
	t.Helper()
	files, err := filepath.Glob("../source/osv/testdata/vulns/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("osv fixtures: %v", err)
	}
	type rec struct{ id, modified string }
	byPkg := map[string][]rec{}
	raw := map[string][]byte{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var v struct {
			ID, Modified string
			Withdrawn    string
			Affected     []struct {
				Package struct{ Ecosystem, Name string }
			}
		}
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatal(err)
		}
		raw[v.ID] = b
		for _, a := range v.Affected {
			k := a.Package.Ecosystem + "|" + a.Package.Name
			byPkg[k] = append(byPkg[k], rec{v.ID, v.Modified})
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Queries []struct {
				Package struct{ Name, Ecosystem string } `json:"package"`
			} `json:"queries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		results := make([]map[string]any, len(req.Queries))
		for i, q := range req.Queries {
			results[i] = map[string]any{}
			var vulns []map[string]string
			for _, v := range byPkg[q.Package.Ecosystem+"|"+q.Package.Name] {
				vulns = append(vulns, map[string]string{"id": v.id, "modified": v.modified})
			}
			if len(vulns) > 0 {
				results[i]["vulns"] = vulns
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	})
	mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, r *http.Request) {
		b, ok := raw[r.PathValue("id")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	})
	return mux
}

// fakeEndOfLife serves source/endoflife/testdata/<product>.json.
func fakeEndOfLife(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		product := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/"), ".json")
		b, err := os.ReadFile(filepath.Join("../source/endoflife/testdata", filepath.Base(product)+".json"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	})
}

// TestEndToEndScan wires the real plugins (github, gomod, golang detector,
// osv, endoflife, memstore, md/json reports, Slack webhook) against fake
// upstreams and checks the whole lifecycle across three scans.
func TestEndToEndScan(t *testing.T) {
	gh := &fakeGitHub{files: map[string]map[string]string{}, sha: map[string]string{}}
	apiMod := "module github.com/acme/api\n\ngo 1.22\n\nrequire (\n\tgoogle.golang.org/protobuf v1.32.0\n\tgithub.com/acme/internal v1.0.0\n)\n"
	gh.set("api", strings.Repeat("a", 40), map[string]string{
		"go.mod":            apiMod,
		"Dockerfile":        "FROM golang:1.22.1-alpine AS build\n",
		"vendor/x/y/go.mod": "module x/y\n\nrequire google.golang.org/protobuf v1.0.0\n", // skipped path
		"README.md":         "# api\n",
	})
	gh.set("web", strings.Repeat("b", 40), map[string]string{"go.mod": "module github.com/acme/web\n\ngo 1.23\n"})
	ghSrv := httptest.NewServer(gh)
	defer ghSrv.Close()
	osvSrv := httptest.NewServer(fakeOSV(t))
	defer osvSrv.Close()
	eolSrv := httptest.NewServer(fakeEndOfLife(t))
	defer eolSrv.Close()
	var slackPosts atomic.Int32
	slackSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slackPosts.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	defer slackSrv.Close()

	t.Setenv("TEST_GH_TOKEN", "test-token")
	t.Setenv("TEST_SLACK_WEBHOOK", slackSrv.URL+"/services/T/B/x")
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "heimdall.yaml")
	cfgYAML := fmt.Sprintf(`
auth_profiles:
  pat: { type: token, token_env: TEST_GH_TOKEN }
targets:
  - { kind: org, name: acme, auth: pat, base_url: %q }
private_modules: ["github.com/acme/*"]
sources:
  osv: { base_url: %q }
  endoflife: { base_url: %q }
notify:
  slack: { type: slack-webhook, webhook_env: TEST_SLACK_WEBHOOK }
report: { formats: [md, json], dir: %q }
store: { type: memory }
cache: { dir: %q }
workspace: { dir: %q }
`, ghSrv.URL, osvSrv.URL, eolSrv.URL, filepath.Join(dir, "reports"), filepath.Join(dir, "cache"), filepath.Join(dir, "ws"))
	if err := os.WriteFile(cfgFile, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ctx := context.Background()
	cat := a.Store.(store.Catalog)
	p := a.Pipeline(cat, a.ConfigProviderFor)
	var events []string
	var evMu sync.Mutex
	prog := core.ProgressFunc(func(level, repo, msg string) {
		evMu.Lock()
		defer evMu.Unlock()
		events = append(events, level+" "+repo+" "+msg)
	})
	scan := func() *model.ScanRun {
		t.Helper()
		run, err := p.Scan(ctx, core.ScanRequest{Targets: a.Targets, Trigger: model.TriggerCLI}, prog)
		if err != nil {
			t.Fatalf("scan: %v\n%s", err, strings.Join(events, "\n"))
		}
		return run
	}

	// ---- run 1: everything is new ----
	run1 := scan()
	if run1.Status != model.RunSucceeded || len(run1.ReposScanned) != 2 {
		t.Fatalf("run1 = %s scanned=%v failed=%v sources=%+v\n%s", run1.Status, run1.ReposScanned, run1.ReposFailed, run1.Sources, strings.Join(events, "\n"))
	}
	open, err := a.Store.ListFindings(ctx, store.FindingFilter{Status: model.StatusOpen})
	if err != nil {
		t.Fatal(err)
	}
	var proto, eol *model.Finding
	for i, f := range open {
		switch {
		case f.Package.Name == "google.golang.org/protobuf":
			proto = &open[i]
		case f.Kind == model.KindRuntime:
			eol = &open[i]
		case f.Package.Name == "github.com/acme/internal":
			t.Fatal("private modules must never be checked against public sources")
		}
	}
	if proto == nil || proto.Repo != "acme/api" || proto.ManifestPath != "go.mod" || proto.AdvisoryID != "GO-2024-2611" ||
		proto.RecommendedVersion != "v1.33.0" || proto.Bump != model.BumpMinor || !proto.Direct {
		t.Fatalf("protobuf finding = %+v\nall: %+v", proto, open)
	}
	if !strings.Contains(strings.Join(proto.Aliases, ","), "CVE-2024-24786") {
		t.Fatalf("aliases = %v", proto.Aliases)
	}
	if eol == nil || eol.Repo != "acme/api" || eol.Runtime == nil || eol.Runtime.Status != model.SupportEOL || eol.Severity != model.SeverityHigh {
		t.Fatalf("Go 1.22 is EOL: want a runtime finding, got %+v", eol)
	}
	if run1.Stats.New != len(open) || run1.Stats.Repos != 2 {
		t.Fatalf("run1 stats = %+v, open = %d", run1.Stats, len(open))
	}
	for _, ext := range []string{".md", ".json"} {
		b, err := os.ReadFile(filepath.Join(dir, "reports", fmt.Sprintf("run-%d%s", run1.ID, ext)))
		if err != nil || !strings.Contains(string(b), "GO-2024-2611") {
			t.Fatalf("report %s: %v", ext, err)
		}
	}
	posts1 := slackPosts.Load()
	if posts1 < 2 { // summary + runtime EOL
		t.Fatalf("slack posts after run1 = %d, want summary and EOL alert", posts1)
	}
	contents1 := gh.contents.Load()

	// ---- run 2: nothing changed ----
	run2 := scan()
	if run2.Stats.New != 0 || run2.Stats.Fixed != 0 {
		t.Fatalf("run2 stats = %+v, want no change", run2.Stats)
	}
	if got := slackPosts.Load() - posts1; got != 1 {
		t.Fatalf("run2 sent %d Slack messages, want only its summary (no repeated alerts)", got)
	}
	if gh.contents.Load() != contents1 {
		t.Fatalf("unchanged HEAD must be read from the workspace cache: contents calls %d → %d", contents1, gh.contents.Load())
	}
	again, _ := a.Store.GetFinding(ctx, proto.ID)
	if !again.FirstSeen.Equal(proto.FirstSeen) {
		t.Fatal("FirstSeen must survive rescans (SLA)")
	}
	if repos, _ := cat.ListRepos(ctx, store.RepoFilter{}); len(repos) != 0 {
		t.Fatalf("config scans without catalog ids must not cache repo lists, got %d", len(repos))
	}

	// ---- run 3: protobuf bumped in a new commit ----
	gh.set("api", strings.Repeat("c", 40), map[string]string{
		"go.mod":     strings.Replace(apiMod, "v1.32.0", "v1.33.0", 1),
		"Dockerfile": "FROM golang:1.23.4\n",
	})
	run3 := scan()
	d, err := a.Store.DiffRuns(ctx, run2.ID, run3.ID)
	if err != nil {
		t.Fatal(err)
	}
	fixed := map[string]bool{}
	for _, f := range d.Fixed {
		fixed[f.ID] = true
	}
	if !fixed[proto.ID] {
		t.Fatalf("bumping protobuf must fix the finding; diff = %+v", d)
	}
	if got, _ := a.Store.GetFinding(ctx, proto.ID); got.Status != model.StatusFixed {
		t.Fatalf("protobuf status = %s, want fixed", got.Status)
	}
}
