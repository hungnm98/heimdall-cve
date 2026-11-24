package recommend

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/core/dedup"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/version"
)

var cmps = dedup.Comparators{model.EcosystemGo: version.Go{}}

func finding(name, ver, adv string, sev model.Severity, direct bool, fixed ...string) model.Finding {
	return model.Finding{
		Kind: model.KindDependency, ManifestPath: "go.mod",
		Package: model.NewPackage(model.EcosystemGo, name, ver), Direct: direct,
		AdvisoryID: adv, Severity: sev, FixedVersions: fixed, Status: model.StatusOpen,
	}
}

func TestPerAdvisoryMinimumThenMax(t *testing.T) {
	fs := []model.Finding{
		// smallest fix above v1.2.0 is 1.2.5 (1.1.9 is below current, 1.3.0 is larger)
		finding("example.com/a", "v1.2.0", "GO-1", model.SeverityMedium, true, "1.1.9", "1.2.5", "1.3.0"),
		// smallest fix is 1.2.7 → package recommendation = max(1.2.5, 1.2.7)
		finding("example.com/a", "v1.2.0", "GO-2", model.SeverityHigh, true, "1.2.7"),
	}
	Apply(fs, cmps)
	for _, f := range fs {
		if f.RecommendedVersion != "v1.2.7" || f.Bump != model.BumpPatch || f.Advice != "go get example.com/a@v1.2.7" {
			t.Errorf("%s: %q %s %q", f.AdvisoryID, f.RecommendedVersion, f.Bump, f.Advice)
		}
	}
	plan := Plan(fs, cmps)
	if len(plan) != 1 {
		t.Fatalf("plan = %+v; want one item per package", plan)
	}
	it := plan[0]
	if it.Recommended != "v1.2.7" || it.Severity != model.SeverityHigh || fmt.Sprint(it.Advisories) != "[GO-1 GO-2]" || !it.Direct || it.Manifest != "go.mod" {
		t.Errorf("item = %+v", it)
	}
}

func TestBumpTypes(t *testing.T) {
	for _, c := range []struct {
		cur, fix string
		want     model.BumpType
	}{
		{"v1.2.0", "1.2.1", model.BumpPatch},
		{"v1.2.0", "1.4.0", model.BumpMinor},
		{"v1.2.0", "2.0.0", model.BumpMajor},
		{"v0.3.0", "0.4.0", model.BumpMajor}, // v0 minor is breaking
		{"v0.0.0-20230101000000-abcdefabcdef", "0.17.0", model.BumpMajor},
		{"v2.0.0+incompatible", "2.0.1+incompatible", model.BumpPatch},
	} {
		fs := []model.Finding{finding("example.com/m", c.cur, "GO-1", model.SeverityHigh, true, c.fix)}
		Apply(fs, cmps)
		if fs[0].Bump != c.want {
			t.Errorf("%s → %s: bump %s; want %s", c.cur, c.fix, fs[0].Bump, c.want)
		}
		if c.want == model.BumpMajor && !strings.Contains(fs[0].Advice, "major upgrade") {
			t.Errorf("major bump advice %q lacks a warning", fs[0].Advice)
		}
	}
}

func TestNoFix(t *testing.T) {
	fs := []model.Finding{
		finding("example.com/a", "v1.0.0", "GO-1", model.SeverityLow, true, "1.1.0"),
		finding("example.com/a", "v1.0.0", "GO-2", model.SeverityCritical, true),
		finding("example.com/b", "v1.0.0", "GO-3", model.SeverityHigh, true, "0.9.0"), // only fix is below current
	}
	mal := finding("example.com/evil", "v1.0.0", "MAL-2024-1", model.SeverityUnknown, true)
	mal.Malicious = true
	fs = append(fs, mal)
	Apply(fs, cmps)
	if fs[0].RecommendedVersion != "v1.1.0" || fs[0].Bump != model.BumpMinor {
		t.Errorf("fixable finding = %q %s", fs[0].RecommendedVersion, fs[0].Bump)
	}
	if fs[1].RecommendedVersion != "" || fs[1].Bump != model.BumpNoFix || !strings.Contains(fs[1].Advice, "no fixed version") {
		t.Errorf("unfixable finding = %q %s %q", fs[1].RecommendedVersion, fs[1].Bump, fs[1].Advice)
	}
	if fs[2].Bump != model.BumpNoFix {
		t.Errorf("fix below current must not count: %s", fs[2].Bump)
	}
	if !strings.Contains(fs[3].Advice, "malicious") {
		t.Errorf("malicious advice = %q", fs[3].Advice)
	}

	plan := Plan(fs, cmps)
	got := []string{}
	for _, it := range plan {
		got = append(got, fmt.Sprintf("%s:%s:%s:%s", it.Package.Name, it.Severity, it.Bump, it.Recommended))
	}
	want := "[example.com/a:CRITICAL:minor:v1.1.0 example.com/b:HIGH:no-fix-available: example.com/evil:UNKNOWN:no-fix-available:]"
	if fmt.Sprint(got) != want {
		t.Errorf("plan = %v\nwant   %s", got, want)
	}
	if !strings.Contains(plan[0].Advice, "no fix yet for GO-2") {
		t.Errorf("partial-fix advice = %q", plan[0].Advice)
	}
}

func TestTransitiveAndStdlibAdvice(t *testing.T) {
	trans := finding("golang.org/x/net", "v0.15.0", "GO-2023-2102", model.SeverityHigh, false, "0.17.0")
	trans.Parents = []string{"google.golang.org/grpc", "example.com/b", "google.golang.org/grpc"}
	orphan := finding("golang.org/x/text", "v0.3.0", "GO-2", model.SeverityLow, false, "0.3.8")
	std := finding("stdlib", "go1.22.1", "GO-2024-2887", model.SeverityUnknown, true, "1.22.4")
	fs := []model.Finding{trans, orphan, std}
	Apply(fs, cmps)
	wantTrans := "go get golang.org/x/net@v0.17.0 (transitive via example.com/b, google.golang.org/grpc: prefer bumping the parent to a release that requires golang.org/x/net >= v0.17.0) (major upgrade: may break the build, needs testing)"
	if fs[0].Advice != wantTrans {
		t.Errorf("transitive advice = %q", fs[0].Advice)
	}
	if fs[1].Advice != "go get golang.org/x/text@v0.3.8 (transitive dependency)" {
		t.Errorf("orphan advice = %q", fs[1].Advice)
	}
	if fs[2].RecommendedVersion != "1.22.4" || fs[2].Bump != model.BumpPatch || fs[2].Advice != "build with Go 1.22.4 or later (go get toolchain@go1.22.4)" {
		t.Errorf("stdlib = %q %s %q", fs[2].RecommendedVersion, fs[2].Bump, fs[2].Advice)
	}
}

func TestPlanSkipsClosedAndGroupsPerManifest(t *testing.T) {
	a := finding("example.com/a", "v1.0.0", "GO-1", model.SeverityHigh, true, "1.0.1")
	b := a
	b.ManifestPath = "tools/go.mod"
	closed := finding("example.com/c", "v1.0.0", "GO-9", model.SeverityCritical, true, "1.0.1")
	closed.Status = model.StatusSuppressed
	plan := Plan([]model.Finding{a, b, closed}, cmps)
	if len(plan) != 2 || plan[0].Manifest != "go.mod" || plan[1].Manifest != "tools/go.mod" {
		t.Errorf("plan = %+v", plan)
	}
}

func TestOtherEcosystemWithoutComparator(t *testing.T) {
	f := model.Finding{Kind: model.KindDependency, ManifestPath: "package-lock.json",
		Package: model.NewPackage(model.EcosystemNPM, "lodash", "4.17.15"), Direct: true,
		AdvisoryID: "GHSA-p6mc-m468-83gw", FixedVersions: []string{"4.17.19"}}
	fs := []model.Finding{f}
	Apply(fs, cmps)
	if fs[0].RecommendedVersion != "4.17.19" || fs[0].Advice != "upgrade lodash to 4.17.19" {
		t.Errorf("npm = %q %q", fs[0].RecommendedVersion, fs[0].Advice)
	}
}

func TestRuntimeAdvice(t *testing.T) {
	eol := time.Date(2024, 8, 13, 0, 0, 0, 0, time.UTC)
	soon := time.Date(2025, 2, 11, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		st   model.RuntimeStatus
		want string
	}{
		{model.RuntimeStatus{Runtime: model.Runtime{Name: "go", Version: "1.21.5"}, Cycle: "1.21", Status: model.SupportEOL, EOLDate: &eol, LatestPatch: "1.21.13", LatestCycle: "1.23"},
			"go 1.21 reached end-of-life on 2024-08-13: migrate to go 1.23"},
		{model.RuntimeStatus{Runtime: model.Runtime{Name: "go", Version: "1.22"}, Cycle: "1.22", Status: model.SupportEOLSoon, EOLDate: &soon, LatestCycle: "1.23"},
			"go 1.22 reaches end-of-life on 2025-02-11: migrate to go 1.23"},
		{model.RuntimeStatus{Runtime: model.Runtime{Name: "go", Version: "go1.23.1"}, Cycle: "1.23", Status: model.SupportSupported, LatestPatch: "1.23.4", LatestCycle: "1.23"},
			"upgrade go to latest patch 1.23.4"},
		{model.RuntimeStatus{Runtime: model.Runtime{Name: "go", Version: "1.23.4"}, Cycle: "1.23", Status: model.SupportSupported, LatestPatch: "1.23.4"}, ""},
		{model.RuntimeStatus{Runtime: model.Runtime{Name: "node", Version: "20"}, Cycle: "20", Status: model.SupportSupported, LatestPatch: "20.18.1"},
			"upgrade node to latest patch 20.18.1"},
		{model.RuntimeStatus{Runtime: model.Runtime{Name: "ruby", Version: "2.7.8"}, Cycle: "2.7", Status: model.SupportEOL},
			"ruby 2.7 reached end-of-life: migrate to a supported ruby release"},
		{model.RuntimeStatus{Runtime: model.Runtime{Name: "go", Version: "1.19"}, Status: model.SupportUnknown}, ""},
	} {
		if got := RuntimeAdvice(c.st); got != c.want {
			t.Errorf("RuntimeAdvice(%+v) = %q; want %q", c.st.Runtime, got, c.want)
		}
	}
	rf := []model.Finding{{Kind: model.KindRuntime, Runtime: &model.RuntimeStatus{Runtime: model.Runtime{Name: "go", Version: "1.21"}, Cycle: "1.21", Status: model.SupportEOL, LatestCycle: "1.23"}}}
	Apply(rf, cmps)
	if rf[0].Advice != "go 1.21 reached end-of-life: migrate to go 1.23" {
		t.Errorf("runtime finding advice = %q", rf[0].Advice)
	}
	if len(Plan(rf, cmps)) != 0 {
		t.Error("runtime findings must not be in the dependency upgrade plan")
	}
}
