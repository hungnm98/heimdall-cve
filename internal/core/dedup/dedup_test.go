package dedup

import (
	"fmt"
	"testing"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/version"
)

var goCmp = Comparators{model.EcosystemGo: version.Go{}}

func goAffected(name string, ranges ...model.VersionRange) model.Affected {
	return model.Affected{Ecosystem: model.EcosystemGo, Name: name, Ranges: ranges}
}

func TestCanonical(t *testing.T) {
	for want, ids := range map[string][]string{
		"GO-2024-2611":        {"CVE-2024-24786", "GHSA-8r3f-844c-mc37", "GO-2024-2611"},
		"GHSA-8r3f-844c-mc37": {"CVE-2024-24786", "GHSA-8r3f-844c-mc37", "PYSEC-1"},
		"CVE-2020-0001":       {"MAL-2024-1", "CVE-2020-0002", "CVE-2020-0001"},
		"MAL-2024-1":          {"OSV-2024-9", "MAL-2024-1"},
		"":                    nil,
	} {
		if got := Canonical(ids); got != want {
			t.Errorf("Canonical(%v) = %q; want %q", ids, got, want)
		}
	}
}

func TestMergeGHSACVEGo(t *testing.T) {
	t1 := time.Date(2024, 3, 5, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2024, 6, 7, 0, 0, 0, 0, time.UTC)
	withdrawn := t2
	advs := []model.Advisory{
		{
			ID: "GHSA-8r3f-844c-mc37", Aliases: []string{"CVE-2024-24786"},
			Summary: "ghsa summary", Severity: model.SeverityMedium, CVSSScore: 5.9, CVSSVector: "CVSS:3.1/x",
			Affected:   []model.Affected{goAffected("google.golang.org/protobuf", model.VersionRange{Introduced: "0", Fixed: "1.33.0"})},
			References: []string{"https://nvd", "https://go.dev/cl/1"}, Sources: []string{"ghsa"}, Published: t2, Modified: t2, Verified: true,
		},
		{
			ID: "GO-2024-2611", Aliases: []string{"CVE-2024-24786"},
			Summary: "go summary", Severity: model.SeverityUnknown,
			Affected:   []model.Affected{goAffected("google.golang.org/protobuf", model.VersionRange{Introduced: "0", Fixed: "1.33.0"})},
			References: []string{"https://go.dev/cl/1"}, Sources: []string{"osv"}, Published: t1, Modified: t1,
		},
		{
			ID: "CVE-2024-24786", Severity: model.SeverityHigh, CVSSScore: 7.5, CVSSVector: "CVSS:3.1/y",
			Sources: []string{"agent"},
		},
		{ID: "GHSA-wwww", Aliases: []string{"CVE-2024-24786"}, Withdrawn: &withdrawn, Sources: []string{"ghsa"}},
		{ID: "GO-2020-0001", Sources: []string{"agent"}, Summary: "unrelated, agent only"},
	}
	got := Merge(advs)
	if len(got) != 2 {
		t.Fatalf("Merge returned %d advisories: %+v", len(got), got)
	}
	m, other := got[1], got[0]
	if m.ID != "GO-2024-2611" || fmt.Sprint(m.Aliases) != "[CVE-2024-24786 GHSA-8r3f-844c-mc37]" {
		t.Errorf("ID/aliases = %s %v", m.ID, m.Aliases)
	}
	if fmt.Sprint(m.Sources) != "[agent ghsa osv]" || !m.Verified {
		t.Errorf("sources = %v verified = %v", m.Sources, m.Verified)
	}
	if m.Severity != model.SeverityHigh || m.CVSSScore != 7.5 || m.CVSSVector != "CVSS:3.1/y" {
		t.Errorf("severity = %s %v %s; want worst/highest", m.Severity, m.CVSSScore, m.CVSSVector)
	}
	if m.Summary != "go summary" || !m.Published.Equal(t1) || !m.Modified.Equal(t2) {
		t.Errorf("summary/published/modified = %q %v %v", m.Summary, m.Published, m.Modified)
	}
	if len(m.Affected) != 1 || len(m.Affected[0].Ranges) != 1 || len(m.References) != 2 {
		t.Errorf("affected/references not unioned: %+v %v", m.Affected, m.References)
	}
	if other.ID != "GO-2020-0001" || other.Verified {
		t.Errorf("agent-only advisory = %+v; want unverified", other)
	}
}

func TestMergeTransitiveAliases(t *testing.T) {
	got := Merge([]model.Advisory{
		{ID: "GHSA-a", Aliases: []string{"CVE-1"}, Sources: []string{"s1"}},
		{ID: "GO-1", Aliases: []string{"GHSA-a"}, Sources: []string{"s2"}},
		{ID: "CVE-1", Sources: []string{"s3"}},
		{ID: "GHSA-b", Sources: []string{"s1"}, Severity: model.SeverityLow},
	})
	if len(got) != 2 || got[0].ID != "GHSA-b" || got[1].ID != "GO-1" || fmt.Sprint(got[1].Sources) != "[s1 s2 s3]" {
		t.Fatalf("Merge = %+v", got)
	}
	if got[1].Severity != model.SeverityUnknown {
		t.Errorf("severity = %q", got[1].Severity)
	}
}

func TestAffects(t *testing.T) {
	g := version.Go{}
	for _, c := range []struct {
		name  string
		af    model.Affected
		v     string
		want  bool
		fixed string
	}{
		{"introduced 0", goAffected("m", model.VersionRange{Introduced: "0", Fixed: "1.2.0"}), "v1.1.9", true, "[1.2.0]"},
		{"fixed is not affected", goAffected("m", model.VersionRange{Introduced: "0", Fixed: "1.2.0"}), "v1.2.0", false, "[]"},
		{"below introduced", goAffected("m", model.VersionRange{Introduced: "1.5.0", Fixed: "1.6.0"}), "v1.4.0", false, "[]"},
		{"at introduced", goAffected("m", model.VersionRange{Introduced: "1.5.0", Fixed: "1.6.0"}), "v1.5.0", true, "[1.6.0]"},
		{"last_affected inclusive", goAffected("m", model.VersionRange{Introduced: "0", LastAffected: "1.3.0"}), "v1.3.0", true, "[]"},
		{"after last_affected", goAffected("m", model.VersionRange{Introduced: "0", LastAffected: "1.3.0"}), "v1.3.1", false, "[]"},
		{"open range", goAffected("m", model.VersionRange{Introduced: "2.0.0"}), "v9.0.0", true, "[]"},
		{"second range", goAffected("m",
			model.VersionRange{Introduced: "0", Fixed: "1.21.11"},
			model.VersionRange{Introduced: "1.22.0-0", Fixed: "1.22.4"}), "1.22.1", true, "[1.22.4]"},
		{"between ranges", goAffected("m",
			model.VersionRange{Introduced: "0", Fixed: "1.21.11"},
			model.VersionRange{Introduced: "1.22.0-0", Fixed: "1.22.4"}), "1.21.12", false, "[]"},
		{"pseudo-version before fix", goAffected("m", model.VersionRange{Introduced: "0", Fixed: "0.17.0"}), "v0.0.0-20230101000000-abcdefabcdef", true, "[0.17.0]"},
		{"pseudo-version prerelease of fix", goAffected("m", model.VersionRange{Introduced: "0", Fixed: "1.2.4"}), "v1.2.4-0.20240101000000-abcdefabcdef", true, "[1.2.4]"},
		{"pseudo-version after fix", goAffected("m", model.VersionRange{Introduced: "0", Fixed: "1.2.4"}), "v1.2.5-0.20240101000000-abcdefabcdef", false, "[]"},
		{"+incompatible affected", goAffected("m", model.VersionRange{Introduced: "0", Fixed: "2.1.0+incompatible"}), "v2.0.0+incompatible", true, "[2.1.0+incompatible]"},
		{"+incompatible fixed", goAffected("m", model.VersionRange{Introduced: "0", Fixed: "2.1.0"}), "v2.1.0+incompatible", false, "[]"},
		{"explicit versions", model.Affected{Ecosystem: model.EcosystemGo, Name: "m", Versions: []string{"1.0.0", "1.0.1"}}, "v1.0.1", true, "[]"},
		{"explicit versions miss", model.Affected{Ecosystem: model.EcosystemGo, Name: "m", Versions: []string{"1.0.0"}}, "v1.0.2", false, "[]"},
		{"invalid bound ignored", goAffected("m", model.VersionRange{Introduced: "0", Fixed: "not-a-version"}), "v1.0.0", false, "[]"},
	} {
		got, fixed := Affects(g, c.af, c.v)
		if got != c.want || fmt.Sprint(fixed) != c.fixed {
			t.Errorf("%s: Affects(%s) = %v %v; want %v %s", c.name, c.v, got, fixed, c.want, c.fixed)
		}
	}
	// No comparator: trust the source, return every fix as a candidate.
	if ok, fixed := Affects(nil, model.Affected{Ranges: []model.VersionRange{{Introduced: "0", Fixed: "4.17.19"}}}, "4.17.15"); !ok || fmt.Sprint(fixed) != "[4.17.19]" {
		t.Errorf("nil comparator = %v %v", ok, fixed)
	}
}

func dep(name, ver string, direct bool, parents ...string) model.Dependency {
	return model.Dependency{Package: model.NewPackage(model.EcosystemGo, name, ver), Direct: direct, Scope: model.ScopeProd, Parents: parents}
}

func TestFindings(t *testing.T) {
	advs := Merge([]model.Advisory{
		{ID: "GHSA-x", Aliases: []string{"CVE-1"}, Severity: model.SeverityHigh, Sources: []string{"ghsa"},
			Affected: []model.Affected{goAffected("example.com/a", model.VersionRange{Introduced: "0", Fixed: "1.2.3"})}},
		{ID: "GO-1", Aliases: []string{"CVE-1"}, Sources: []string{"osv"},
			Affected: []model.Affected{goAffected("example.com/a", model.VersionRange{Introduced: "0", Fixed: "1.2.4"})}},
		{ID: "GO-2", Sources: []string{"osv"}, Severity: model.SeverityLow,
			Affected: []model.Affected{goAffected("example.com/a", model.VersionRange{Introduced: "2.0.0", Fixed: "2.0.1"})}},
		{ID: "GO-3", Sources: []string{"osv"},
			Affected: []model.Affected{goAffected("stdlib", model.VersionRange{Introduced: "0", Fixed: "1.21.11"}, model.VersionRange{Introduced: "1.22.0-0", Fixed: "1.22.4"})}},
		{ID: "MAL-2024-1", Sources: []string{"osv"},
			Affected: []model.Affected{{Ecosystem: model.EcosystemGo, Name: "example.com/evil", Versions: []string{"1.0.0"}}}},
	})
	private := dep("example.com/a", "v1.0.0", true)
	private.Private = true
	unresolvable := dep("example.com/a", "v1.0.0", true)
	unresolvable.Unresolvable = "local replace"
	graphs := []model.DependencyGraph{
		{Ecosystem: model.EcosystemGo, ManifestPath: "go.mod", Dependencies: []model.Dependency{
			dep("example.com/a", "v1.2.0", false, "example.com/parent"),
			dep("example.com/a", "v1.2.0", true), // listed twice: must collapse
			dep("stdlib", "go1.22.1", true),
			dep("example.com/evil", "v1.0.0", true),
			dep("example.com/clean", "v1.0.0", true),
		}},
		{Ecosystem: model.EcosystemGo, ManifestPath: "tools/go.mod", Dependencies: []model.Dependency{
			dep("example.com/a", "v1.2.4", true), // fixed for GO-1, not in GO-2 range
			private, unresolvable,
		}},
	}
	got := Findings(Location{Provider: "github", Repo: "acme/api"}, graphs, advs, goCmp)
	if len(got) != 3 {
		t.Fatalf("got %d findings: %+v", len(got), got)
	}
	a := got[0]
	if a.Package.Name != "example.com/a" || a.AdvisoryID != "GO-1" || fmt.Sprint(a.Aliases) != "[CVE-1 GHSA-x]" {
		t.Errorf("finding a = %+v", a)
	}
	if !a.Direct || fmt.Sprint(a.Parents) != "[example.com/parent]" || fmt.Sprint(a.Sources) != "[ghsa osv]" || a.Severity != model.SeverityHigh {
		t.Errorf("collapsed finding = direct %v parents %v sources %v sev %s", a.Direct, a.Parents, a.Sources, a.Severity)
	}
	// GHSA says fixed 1.2.3 but GO-1 still affects 1.2.3: only 1.2.4 is a real fix.
	if fmt.Sprint(a.FixedVersions) != "[1.2.4]" {
		t.Errorf("fixed = %v; want [1.2.4]", a.FixedVersions)
	}
	want := model.FindingID("github", "acme/api", "go.mod", a.Package.Key(), "GO-1")
	if a.ID != want || a.Kind != model.KindDependency || a.Status != model.StatusOpen || !a.Verified {
		t.Errorf("identity = %s kind %s status %s verified %v", a.ID, a.Kind, a.Status, a.Verified)
	}
	if mal := got[1]; mal.AdvisoryID != "MAL-2024-1" || !mal.Malicious || len(mal.FixedVersions) != 0 {
		t.Errorf("malicious finding = %+v", mal)
	}
	if std := got[2]; std.Package.Name != "stdlib" || std.AdvisoryID != "GO-3" || fmt.Sprint(std.FixedVersions) != "[1.22.4]" {
		t.Errorf("stdlib finding = %+v", std)
	}
	seen := map[string]bool{}
	for _, f := range got {
		if seen[f.ID] {
			t.Errorf("duplicate finding ID %s", f.ID)
		}
		seen[f.ID] = true
	}
}

func TestFindingIDStableAcrossVersions(t *testing.T) {
	advs := []model.Advisory{{ID: "GO-1", Sources: []string{"osv"},
		Affected: []model.Affected{goAffected("example.com/a", model.VersionRange{Introduced: "0", Fixed: "2.0.0"})}}}
	loc := Location{Provider: "github", Repo: "acme/api"}
	f1 := Findings(loc, []model.DependencyGraph{{ManifestPath: "go.mod", Dependencies: []model.Dependency{dep("example.com/a", "v1.0.0", true)}}}, advs, goCmp)
	f2 := Findings(loc, []model.DependencyGraph{{ManifestPath: "go.mod", Dependencies: []model.Dependency{dep("example.com/a", "v1.5.0", true)}}}, advs, goCmp)
	if len(f1) != 1 || len(f2) != 1 || f1[0].ID != f2[0].ID {
		t.Fatalf("finding ID must not depend on version: %v %v", f1, f2)
	}
}
