package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/config"
	"github.com/hungnm98/heimdall-cve/internal/core"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

// TestEndToEndPolyglot scans one repo holding a Go service, a Node.js web app
// and a Ruby app: every ecosystem and runtime must be found in one pass,
// with ecosystem-specific versions, advice and EOL runtimes.
func TestEndToEndPolyglot(t *testing.T) {
	gh := &fakeGitHub{files: map[string]map[string]string{}, sha: map[string]string{}}
	gh.set("mono", strings.Repeat("d", 40), map[string]string{
		"services/api/go.mod":     "module github.com/acme/mono/api\n\ngo 1.22\n\nrequire google.golang.org/protobuf v1.32.0\n",
		"services/api/Dockerfile": "FROM golang:1.23.4 AS build\n",
		"web/package.json":        `{"name":"web","dependencies":{"lodash":"^4.17.15","evil-helper":"1.0.0","@acme/ui":"^2.0.0"}}`,
		"web/package-lock.json": `{"name":"web","lockfileVersion":3,"requires":true,"packages":{
			"":{"name":"web","dependencies":{"lodash":"^4.17.15","evil-helper":"1.0.0","@acme/ui":"^2.0.0"}},
			"node_modules/lodash":{"version":"4.17.15"},
			"node_modules/evil-helper":{"version":"1.0.0"},
			"node_modules/@acme/ui":{"version":"2.1.0"}}}`,
		"web/.nvmrc":                      "16\n",
		"web/node_modules/x/package.json": `{"name":"x","dependencies":{"lodash":"1.0.0"}}`, // skipped path
		"billing/Gemfile.lock": "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.8)\n\nPLATFORMS\n  ruby\n\n" +
			"DEPENDENCIES\n  rack\n\nRUBY VERSION\n   ruby 3.0.6p216\n\nBUNDLED WITH\n   2.4.10\n",
	})
	ghSrv := httptest.NewServer(gh)
	defer ghSrv.Close()
	osvSrv := httptest.NewServer(fakeOSV(t))
	defer osvSrv.Close()
	eolSrv := httptest.NewServer(fakeEndOfLife(t))
	defer eolSrv.Close()
	var slackPosts atomic.Int32
	var malAlert atomic.Bool
	slackSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), "MALICIOUS") {
			malAlert.Store(true)
		}
		slackPosts.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	defer slackSrv.Close()

	t.Setenv("TEST_GH_TOKEN", "test-token")
	t.Setenv("TEST_SLACK_WEBHOOK", slackSrv.URL+"/services/T/B/x")
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "heimdall.yaml")
	if err := os.WriteFile(cfgFile, []byte(fmt.Sprintf(`
auth_profiles:
  pat: { type: token, token_env: TEST_GH_TOKEN }
targets:
  - { kind: org, name: acme, auth: pat, base_url: %q }
private_modules: ["github.com/acme/*", "@acme/*"]
sources:
  osv: { base_url: %q }
  endoflife: { base_url: %q }
notify:
  slack: { type: slack-webhook, webhook_env: TEST_SLACK_WEBHOOK }
report: { formats: [md, json], dir: %q }
store: { type: memory }
cache: { dir: %q }
workspace: { dir: %q }
`, ghSrv.URL, osvSrv.URL, eolSrv.URL, filepath.Join(dir, "reports"), filepath.Join(dir, "cache"), filepath.Join(dir, "ws"))), 0o600); err != nil {
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
	if len(a.Ecosystems) < 3 {
		t.Fatalf("every compiled-in ecosystem must be on by default, got %d", len(a.Ecosystems))
	}
	ctx := context.Background()
	var log []string
	run, err := a.Pipeline(a.Store.(store.Catalog), a.ConfigProviderFor).Scan(ctx,
		core.ScanRequest{Targets: a.Targets, Trigger: model.TriggerCLI},
		core.ProgressFunc(func(level, repo, msg string) { log = append(log, level+" "+repo+" "+msg) }))
	if err != nil || run.Status != model.RunSucceeded {
		t.Fatalf("scan: %v %+v\n%s", err, run, strings.Join(log, "\n"))
	}
	open, err := a.Store.ListFindings(ctx, store.FindingFilter{Status: model.StatusOpen})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]model.Finding{}
	for _, f := range open {
		key := string(f.Package.Ecosystem) + ":" + f.Package.Name
		if f.Kind == model.KindRuntime {
			key = "runtime:" + f.Runtime.Runtime.Name
		}
		got[key] = f
	}
	want := []struct {
		key, manifest, rec string
		bump               model.BumpType
	}{
		{"go:google.golang.org/protobuf", "services/api/go.mod", "v1.33.0", model.BumpMinor},
		{"npm:lodash", "web/package-lock.json", "4.17.19", model.BumpPatch},
		{"npm:evil-helper", "web/package-lock.json", "", model.BumpNoFix},
		{"rubygems:rack", "billing/Gemfile.lock", "2.2.8.1", model.BumpPatch},
	}
	for _, w := range want {
		f, ok := got[w.key]
		if !ok {
			t.Errorf("missing finding %s; have %v\n%s", w.key, keys(got), strings.Join(log, "\n"))
			continue
		}
		if f.ManifestPath != w.manifest || f.RecommendedVersion != w.rec || f.Bump != w.bump {
			t.Errorf("%s: manifest=%s rec=%q bump=%q advice=%q; want %s %q %q", w.key, f.ManifestPath, f.RecommendedVersion, f.Bump, f.Advice, w.manifest, w.rec, w.bump)
		}
	}
	if f := got["npm:lodash"]; !strings.Contains(f.Advice, "npm install lodash@4.17.19") {
		t.Errorf("npm advice = %q", f.Advice)
	}
	if f := got["rubygems:rack"]; !strings.Contains(f.Advice, "bundle update rack") {
		t.Errorf("ruby advice = %q", f.Advice)
	}
	if f := got["npm:evil-helper"]; !f.Malicious || f.Severity != model.SeverityCritical || !strings.Contains(f.Advice, "remove evil-helper") {
		t.Errorf("malicious package: %+v", f)
	}
	for _, rt := range []string{"runtime:node", "runtime:ruby", "runtime:go"} {
		if f, ok := got[rt]; !ok || f.Runtime.Status != model.SupportEOL {
			t.Errorf("%s must be reported EOL (node 16, ruby 3.0, go 1.22), got %+v", rt, f.Runtime)
		}
	}
	for k := range got {
		if strings.Contains(k, "@acme/ui") {
			t.Error("private npm scope must never reach public sources")
		}
	}
	if !malAlert.Load() {
		t.Error("a new malicious package must trigger an immediate Slack alert")
	}
}

func keys(m map[string]model.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
