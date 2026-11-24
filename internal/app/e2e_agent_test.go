package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/config"
	"github.com/hungnm98/heimdall-cve/internal/core"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

// TestEndToEndAgentSource: scans record the inventory; advisories submitted
// by AI agents become unverified findings, and merge into the public record
// (verified) when they share an alias with it.
func TestEndToEndAgentSource(t *testing.T) {
	gh := &fakeGitHub{files: map[string]map[string]string{}, sha: map[string]string{}}
	gh.set("web", strings.Repeat("e", 40), map[string]string{
		"package.json": `{"name":"web","dependencies":{"lodash":"^4.17.15","left-pad":"1.3.0","@acme/ui":"2.0.0"}}`,
		"package-lock.json": `{"name":"web","lockfileVersion":3,"requires":true,"packages":{
			"":{"name":"web","dependencies":{"lodash":"^4.17.15","left-pad":"1.3.0","@acme/ui":"2.0.0"}},
			"node_modules/lodash":{"version":"4.17.15"},
			"node_modules/left-pad":{"version":"1.3.0"},
			"node_modules/@acme/ui":{"version":"2.0.0"}}}`,
	})
	ghSrv := httptest.NewServer(gh)
	defer ghSrv.Close()
	osvSrv := httptest.NewServer(fakeOSV(t))
	defer osvSrv.Close()
	t.Setenv("TEST_GH_TOKEN", "test-token")
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "heimdall.yaml")
	if err := os.WriteFile(cfgFile, []byte(fmt.Sprintf(`
auth_profiles: { pat: { type: token, token_env: TEST_GH_TOKEN } }
targets: [ { kind: org, name: acme, auth: pat, base_url: %q } ]
private_modules: ["@acme/*"]
sources: { osv: { base_url: %q } }
store: { type: memory }
report: { formats: [] }
cache: { dir: %q }
workspace: { dir: %q }
`, ghSrv.URL, osvSrv.URL, filepath.Join(dir, "cache"), filepath.Join(dir, "ws"))), 0o600); err != nil {
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
	in := a.Store.(store.Intel)
	p := a.Pipeline(a.Store.(store.Catalog), a.ConfigProviderFor)
	scan := func() {
		t.Helper()
		if _, err := p.Scan(ctx, core.ScanRequest{Targets: a.Targets}, nil); err != nil {
			t.Fatal(err)
		}
	}
	scan()

	inv, err := in.ListInventory(ctx, store.InventoryFilter{Repo: "acme/web"})
	if err != nil || len(inv) != 3 {
		t.Fatalf("inventory = %+v, %v; want lodash, left-pad and the private @acme/ui", inv, err)
	}
	usage, _ := in.PackageUsage(ctx, store.UsageFilter{})
	for _, u := range usage {
		if u.Name == "@acme/ui" {
			t.Fatal("private packages must not appear in usage (they are never sent to agents' public research)")
		}
	}

	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	npmAffected := func(name, fixed string) []model.Affected {
		return []model.Affected{{Ecosystem: model.EcosystemNPM, Name: name, Ranges: []model.VersionRange{{Introduced: "0", Fixed: fixed}}}}
	}
	// 1. A zero-day OSV does not know yet.
	if err := in.SaveAgentAdvisory(ctx, &model.AgentAdvisory{
		Advisory: model.Advisory{ID: "HEIMDALL-AGENT-2026-0001", Summary: "left-pad 1.3.0 tarball contains a credential stealer",
			Severity: model.SeverityCritical, Affected: npmAffected("left-pad", "1.3.1")},
		Evidence: []string{"https://example.com/report"}, Confidence: model.ConfidenceHigh, SubmittedBy: "agent", SubmittedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	// 2. The same vulnerability as a public GHSA record, under another id.
	if err := in.SaveAgentAdvisory(ctx, &model.AgentAdvisory{
		Advisory: model.Advisory{ID: "HEIMDALL-AGENT-2026-0002", Aliases: []string{"GHSA-p6mc-m468-83gw"},
			Summary: "lodash prototype pollution", Affected: npmAffected("lodash", "4.17.19")},
		Evidence: []string{"https://example.com/lodash"}, Confidence: model.ConfidenceMedium, SubmittedBy: "agent", SubmittedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	scan()

	open, err := a.Store.ListFindings(ctx, store.FindingFilter{Status: model.StatusOpen})
	if err != nil {
		t.Fatal(err)
	}
	var leftPad, lodash []model.Finding
	for _, f := range open {
		switch f.Package.Name {
		case "left-pad":
			leftPad = append(leftPad, f)
		case "lodash":
			lodash = append(lodash, f)
		}
	}
	if len(leftPad) != 1 || leftPad[0].Verified || leftPad[0].Sources[0] != model.AgentSource || leftPad[0].RecommendedVersion != "1.3.1" {
		t.Fatalf("agent-only advisory must give one unverified finding: %+v", leftPad)
	}
	if len(lodash) != 1 || !lodash[0].Verified || !strings.Contains(strings.Join(lodash[0].Sources, ","), model.AgentSource) {
		t.Fatalf("an agent advisory sharing an alias with OSV must merge into one verified finding: %+v", lodash)
	}
}
