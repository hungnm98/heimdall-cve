// Package reporttest is the contract test kit for report.Reporter, with golden-file support.
package reporttest

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/report"
)

var update = flag.Bool("update", false, "rewrite golden files")

// Sample returns a small, fully populated report for golden tests.
func Sample() *model.Report {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	eol := time.Date(2026, 2, 11, 0, 0, 0, 0, time.UTC)
	pkg := model.NewPackage(model.EcosystemGo, "golang.org/x/net", "v0.20.0")
	f := model.Finding{
		ID: "f1", Kind: model.KindDependency, Provider: "github", Repo: "acme/api", ManifestPath: "go.mod",
		Package: pkg, Direct: true, Scope: model.ScopeProd, AdvisoryID: "GO-2024-2687",
		Aliases: []string{"CVE-2023-45288", "GHSA-4v7x-pqxf-cx7m"}, Summary: "HTTP/2 CONTINUATION flood",
		Severity: model.SeverityHigh, CVSSScore: 7.5, FixedVersions: []string{"v0.23.0"},
		RecommendedVersion: "v0.23.0", Bump: model.BumpMinor, Advice: "go get golang.org/x/net@v0.23.0",
		Sources: []string{"osv"}, Verified: true, FirstSeen: at, LastSeen: at, Status: model.StatusOpen,
	}
	run := model.ScanRun{ID: 7, StartedAt: at, FinishedAt: at.Add(90 * time.Second), Status: model.RunSucceeded,
		ReposScanned: []string{"acme/api"}, Sources: []model.SourceHealth{{Name: "osv", Healthy: true, Calls: 1}}}
	return &model.Report{
		Run: run, GeneratedAt: at,
		Repos: []model.RepoReport{{
			Repo:     model.Repo{Provider: "github", Owner: "acme", Name: "api", HTMLURL: "https://github.com/acme/api", Ref: "main"},
			HeadSHA:  "0123456789abcdef",
			Findings: []model.Finding{f},
			Runtimes: []model.RuntimeStatus{{
				Runtime: model.Runtime{Name: "go", Version: "1.24", Origin: "go.mod", Via: "go directive"},
				Cycle:   "1.24", Status: model.SupportEOL, EOLDate: &eol, LatestPatch: "1.24.13", LatestCycle: "1.26", Source: "endoflife",
			}},
			UpgradePlan: []model.UpgradeItem{{Package: pkg, Manifest: "go.mod", Direct: true, Recommended: "v0.23.0",
				Bump: model.BumpMinor, Severity: model.SeverityHigh, Advisories: []string{"GO-2024-2687"}, Advice: f.Advice}},
		}},
		Diff: &model.Diff{FromRun: 6, ToRun: 7, New: []model.Finding{f}},
	}
}

// Run checks the contract (deterministic, handles an empty report) and
// compares Sample() output with testdata/golden<ext>. Run `go test -update` to rewrite it.
func Run(t *testing.T, r report.Reporter) {
	t.Helper()
	if r.Format() == "" || !strings.HasPrefix(r.FileExtension(), ".") {
		t.Fatal("Format() must be set and FileExtension() start with '.'")
	}
	var empty bytes.Buffer
	if err := r.Render(&empty, &model.Report{}); err != nil {
		t.Errorf("Render(empty report): %v", err)
	}
	var a, b bytes.Buffer
	if err := r.Render(&a, Sample()); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if err := r.Render(&b, Sample()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("Render output is not deterministic")
	}
	Golden(t, "golden"+r.FileExtension(), a.Bytes())
}

// Golden compares got with testdata/<name>, rewriting it under -update.
func Golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read golden %s (run `go test -update` to create it): %v", p, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output differs from %s (run `go test -update` if intended)\n--- got ---\n%s", p, got)
	}
}
