package storetest

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

// RunIntel executes the store.Intel contract. newStore must return a fresh,
// migrated-or-migratable store that implements store.Intel.
func RunIntel(t *testing.T, newStore func(t *testing.T) store.Store) {
	t.Helper()
	open := func(t *testing.T) store.Intel {
		s := newStore(t)
		if err := s.Migrate(context.Background()); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		in, ok := s.(store.Intel)
		if !ok {
			t.Fatalf("%T does not implement store.Intel", s)
		}
		return in
	}
	t.Run("Inventory", func(t *testing.T) { testInventory(t, open(t)) })
	t.Run("InventoryLarge", func(t *testing.T) { testInventoryLarge(t, open(t)) })
	t.Run("PackageUsage", func(t *testing.T) { testPackageUsage(t, open(t)) })
	t.Run("AgentAdvisories", func(t *testing.T) { testAgentAdvisories(t, open(t)) })
	t.Run("Analyses", func(t *testing.T) { testAnalyses(t, open(t)) })
	t.Run("Concurrent", func(t *testing.T) { testIntelConcurrent(t, open(t)) })
}

func inv(manifest string, eco model.Ecosystem, name, version string, direct bool) model.InventoryItem {
	return model.InventoryItem{ManifestPath: manifest, Package: model.NewPackage(eco, name, version),
		Direct: direct, Scope: model.ScopeProd}
}

// invKey renders an item for order/equality checks.
func invKey(it model.InventoryItem) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s", it.Repo, it.ManifestPath, it.Package.Ecosystem, it.Package.Name, it.Package.Version)
}

func invKeys(items []model.InventoryItem) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = invKey(it)
	}
	return out
}

func listInv(t *testing.T, in store.Intel, f store.InventoryFilter) []model.InventoryItem {
	t.Helper()
	got, err := in.ListInventory(context.Background(), f)
	must(t, err)
	return got
}

func wantInv(t *testing.T, what string, got []model.InventoryItem, want ...string) {
	t.Helper()
	if g := invKeys(got); !slices.Equal(g, want) {
		t.Fatalf("%s:\n got %q\nwant %q", what, g, want)
	}
}

func testInventory(t *testing.T, in store.Intel) {
	ctx := context.Background()
	if got := listInv(t, in, store.InventoryFilter{}); len(got) != 0 {
		t.Fatalf("empty store: %+v", got)
	}
	priv := inv("go.mod", model.EcosystemGo, "corp.example/lib", "v1.0.0", true)
	priv.Private = true
	priv.Scope = model.ScopeDev
	unres := inv("package.json", model.EcosystemNPM, "@corp/ui", "", false)
	unres.Unresolvable = "no lockfile"
	unres.Scope = model.ScopeOptional
	a := []model.InventoryItem{
		inv("package.json", model.EcosystemNPM, "lodash", "4.17.21", true),
		inv("go.mod", model.EcosystemGo, "golang.org/x/net", "v0.1.0", false),
		inv("go.mod", model.EcosystemGo, "github.com/pkg/errors", "v0.9.1", true),
		priv,
		unres,
		{Repo: "ignored/by-argument", ManifestPath: "Gemfile.lock", Package: model.NewPackage(model.EcosystemRubyGems, "rails", "7.1.0"), Direct: true},
	}
	must(t, in.ReplaceInventory(ctx, "o/a", a, t0))
	must(t, in.ReplaceInventory(ctx, "o/b", []model.InventoryItem{
		inv("go.mod", model.EcosystemGo, "golang.org/x/net", "v0.2.0", true),
		inv("sub/go.mod", model.EcosystemGo, "golang.org/x/net", "v0.1.0", false),
	}, t0))

	all := listInv(t, in, store.InventoryFilter{})
	wantInv(t, "ordered by repo, manifest, ecosystem, name, version", all,
		"o/a|Gemfile.lock|rubygems|rails|7.1.0",
		"o/a|go.mod|go|corp.example/lib|v1.0.0",
		"o/a|go.mod|go|github.com/pkg/errors|v0.9.1",
		"o/a|go.mod|go|golang.org/x/net|v0.1.0",
		"o/a|package.json|npm|@corp/ui|",
		"o/a|package.json|npm|lodash|4.17.21",
		"o/b|go.mod|go|golang.org/x/net|v0.2.0",
		"o/b|sub/go.mod|go|golang.org/x/net|v0.1.0",
	)
	// Every field round-trips; Repo comes from the argument.
	byKey := map[string]model.InventoryItem{}
	for _, it := range all {
		byKey[invKey(it)] = it
	}
	wantP := priv
	wantP.Repo = "o/a"
	if got := byKey["o/a|go.mod|go|corp.example/lib|v1.0.0"]; got != wantP {
		t.Fatalf("private item = %+v, want %+v", got, wantP)
	}
	wantU := unres
	wantU.Repo = "o/a"
	if got := byKey["o/a|package.json|npm|@corp/ui|"]; got != wantU {
		t.Fatalf("unresolvable item = %+v, want %+v", got, wantU)
	}
	if got := byKey["o/a|Gemfile.lock|rubygems|rails|7.1.0"]; got.Repo != "o/a" || got.Package.PURL == "" || !got.Direct {
		t.Fatalf("item must take repo from the argument and keep its PURL: %+v", got)
	}

	// Filters.
	wantInv(t, "repo", listInv(t, in, store.InventoryFilter{Repo: "o/b"}),
		"o/b|go.mod|go|golang.org/x/net|v0.2.0", "o/b|sub/go.mod|go|golang.org/x/net|v0.1.0")
	wantInv(t, "ecosystem", listInv(t, in, store.InventoryFilter{Ecosystem: model.EcosystemNPM}),
		"o/a|package.json|npm|@corp/ui|", "o/a|package.json|npm|lodash|4.17.21")
	wantInv(t, "name", listInv(t, in, store.InventoryFilter{Name: "golang.org/x/net"}),
		"o/a|go.mod|go|golang.org/x/net|v0.1.0", "o/b|go.mod|go|golang.org/x/net|v0.2.0", "o/b|sub/go.mod|go|golang.org/x/net|v0.1.0")
	wantInv(t, "direct only", listInv(t, in, store.InventoryFilter{Ecosystem: model.EcosystemGo, DirectOnly: true}),
		"o/a|go.mod|go|corp.example/lib|v1.0.0", "o/a|go.mod|go|github.com/pkg/errors|v0.9.1", "o/b|go.mod|go|golang.org/x/net|v0.2.0")
	wantInv(t, "combined", listInv(t, in, store.InventoryFilter{Repo: "o/a", Name: "golang.org/x/net"}),
		"o/a|go.mod|go|golang.org/x/net|v0.1.0")
	wantInv(t, "limit", listInv(t, in, store.InventoryFilter{Limit: 2}),
		"o/a|Gemfile.lock|rubygems|rails|7.1.0", "o/a|go.mod|go|corp.example/lib|v1.0.0")
	wantInv(t, "no match", listInv(t, in, store.InventoryFilter{Repo: "o/none"}))

	// A second replace drops the old items of that repo only.
	must(t, in.ReplaceInventory(ctx, "o/a", []model.InventoryItem{
		inv("package.json", model.EcosystemNPM, "lodash", "4.17.22", true),
	}, t0.Add(time.Hour)))
	wantInv(t, "after replace", listInv(t, in, store.InventoryFilter{}),
		"o/a|package.json|npm|lodash|4.17.22",
		"o/b|go.mod|go|golang.org/x/net|v0.2.0",
		"o/b|sub/go.mod|go|golang.org/x/net|v0.1.0",
	)
	// Replacing with nothing empties the repo.
	must(t, in.ReplaceInventory(ctx, "o/a", nil, t0.Add(2*time.Hour)))
	wantInv(t, "after empty replace", listInv(t, in, store.InventoryFilter{Repo: "o/a"}))
	if got := listInv(t, in, store.InventoryFilter{}); len(got) != 2 {
		t.Fatalf("other repos must be untouched: %q", invKeys(got))
	}
}

func testInventoryLarge(t *testing.T, in store.Intel) {
	ctx := context.Background()
	const n = 5000
	gen := func(ver string) []model.InventoryItem {
		items := make([]model.InventoryItem, n)
		for i := range items {
			items[i] = inv("package-lock.json", model.EcosystemNPM, fmt.Sprintf("pkg-%05d", i), ver, i%10 == 0)
		}
		return items
	}
	must(t, in.ReplaceInventory(ctx, "o/big", gen("1.0.0"), t0))
	must(t, in.ReplaceInventory(ctx, "o/small", []model.InventoryItem{inv("go.mod", model.EcosystemGo, "x", "v1", true)}, t0))
	must(t, in.ReplaceInventory(ctx, "o/big", gen("2.0.0"), t0.Add(time.Hour)))
	got := listInv(t, in, store.InventoryFilter{Repo: "o/big"})
	if len(got) != n {
		t.Fatalf("large replace: %d items, want %d", len(got), n)
	}
	for i, it := range got {
		if want := fmt.Sprintf("pkg-%05d", i); it.Package.Name != want || it.Package.Version != "2.0.0" || it.Direct != (i%10 == 0) {
			t.Fatalf("item %d = %+v, want %s@2.0.0", i, it, want)
		}
	}
	if got := listInv(t, in, store.InventoryFilter{DirectOnly: true, Repo: "o/big"}); len(got) != n/10 {
		t.Fatalf("direct items = %d, want %d", len(got), n/10)
	}
	if got := listInv(t, in, store.InventoryFilter{Repo: "o/small"}); len(got) != 1 {
		t.Fatalf("other repo touched by large replace: %+v", got)
	}
}

func usage(t *testing.T, in store.Intel, f store.UsageFilter) []model.PackageUsage {
	t.Helper()
	got, err := in.PackageUsage(context.Background(), f)
	must(t, err)
	return got
}

func usageNames(us []model.PackageUsage) []string {
	out := make([]string, len(us))
	for i, u := range us {
		out[i] = string(u.Ecosystem) + ":" + u.Name
	}
	return out
}

func testPackageUsage(t *testing.T, in store.Intel) {
	ctx := context.Background()
	if got := usage(t, in, store.UsageFilter{}); len(got) != 0 {
		t.Fatalf("empty store: %+v", got)
	}
	priv := inv("go.mod", model.EcosystemGo, "corp.example/lib", "v1.0.0", true)
	priv.Private = true
	unres := inv("package.json", model.EcosystemNPM, "@corp/unresolvable", "", true)
	unres.Unresolvable = "range only"
	must(t, in.ReplaceInventory(ctx, "o/c", []model.InventoryItem{
		inv("go.mod", model.EcosystemGo, "golang.org/x/net", "v0.2.0", false),
		inv("package.json", model.EcosystemNPM, "lodash", "4.17.21", false),
		inv("package.json", model.EcosystemNPM, "left-pad", "1.3.0", false),
		priv, unres,
	}, t0))
	must(t, in.ReplaceInventory(ctx, "o/a", []model.InventoryItem{
		inv("go.mod", model.EcosystemGo, "golang.org/x/net", "v0.1.0", false),
		inv("sub/go.mod", model.EcosystemGo, "golang.org/x/net", "v0.2.0", false),
		inv("package.json", model.EcosystemNPM, "lodash", "4.17.20", true),
		inv("Gemfile.lock", model.EcosystemRubyGems, "rails", "7.1.0", true),
		priv,
	}, t0))
	must(t, in.ReplaceInventory(ctx, "o/b", []model.InventoryItem{
		inv("go.mod", model.EcosystemGo, "golang.org/x/net", "v0.1.0", false),
		inv("Gemfile.lock", model.EcosystemRubyGems, "rails", "7.1.0", false),
	}, t0))

	all := usage(t, in, store.UsageFilter{})
	// 3 repos; then 2 repos (npm < rubygems); then 1 repo.
	want := []model.PackageUsage{
		{Ecosystem: model.EcosystemGo, Name: "golang.org/x/net", Versions: []string{"v0.1.0", "v0.2.0"}, Repos: []string{"o/a", "o/b", "o/c"}},
		{Ecosystem: model.EcosystemNPM, Name: "lodash", Versions: []string{"4.17.20", "4.17.21"}, Repos: []string{"o/a", "o/c"}, Direct: true},
		{Ecosystem: model.EcosystemRubyGems, Name: "rails", Versions: []string{"7.1.0"}, Repos: []string{"o/a", "o/b"}, Direct: true},
		{Ecosystem: model.EcosystemNPM, Name: "left-pad", Versions: []string{"1.3.0"}, Repos: []string{"o/c"}},
	}
	if !reflect.DeepEqual(all, want) {
		t.Fatalf("PackageUsage (private/unresolvable excluded, distinct sorted, direct anywhere):\n got %+v\nwant %+v", all, want)
	}
	if got := usageNames(usage(t, in, store.UsageFilter{DirectOnly: true})); !slices.Equal(got, []string{"npm:lodash", "rubygems:rails"}) {
		t.Fatalf("direct only = %q", got)
	}
	if got := usageNames(usage(t, in, store.UsageFilter{Ecosystem: model.EcosystemNPM})); !slices.Equal(got, []string{"npm:lodash", "npm:left-pad"}) {
		t.Fatalf("ecosystem = %q", got)
	}
	if got := usageNames(usage(t, in, store.UsageFilter{Limit: 2})); !slices.Equal(got, []string{"go:golang.org/x/net", "npm:lodash"}) {
		t.Fatalf("limit = %q", got)
	}
	if got := usageNames(usage(t, in, store.UsageFilter{Ecosystem: model.EcosystemNPM, DirectOnly: true, Limit: 1})); !slices.Equal(got, []string{"npm:lodash"}) {
		t.Fatalf("combined = %q", got)
	}
	// Usage follows inventory replacement.
	must(t, in.ReplaceInventory(ctx, "o/c", nil, t0.Add(time.Hour)))
	if got := usageNames(usage(t, in, store.UsageFilter{})); !slices.Equal(got, []string{"go:golang.org/x/net", "rubygems:rails", "npm:lodash"}) {
		t.Fatalf("after replace = %q", got)
	}
}

func agentAdvisory(id string) *model.AgentAdvisory {
	withdrawn := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	return &model.AgentAdvisory{
		Advisory: model.Advisory{
			ID: id, Aliases: []string{"CVE-2026-0001", "GHSA-xxxx-yyyy-zzzz"},
			Summary: "prototype pollution", Details: "Long details\nwith lines.",
			Severity: model.SeverityHigh, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", CVSSScore: 8.1,
			Affected: []model.Affected{
				{Ecosystem: model.EcosystemNPM, Name: "lodash",
					Ranges:   []model.VersionRange{{Introduced: "0", Fixed: "4.17.22"}, {Introduced: "5.0.0", LastAffected: "5.0.1"}},
					Versions: []string{"4.17.20", "4.17.21"}},
				{Ecosystem: model.EcosystemNPM, Name: "lodash-es", Ranges: []model.VersionRange{{Introduced: "0"}}},
			},
			References: []string{"https://example.com/advisory"},
			Published:  time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
			Modified:   time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC),
			Withdrawn:  &withdrawn,
			Sources:    []string{model.AgentSource},
		},
		Evidence:    []string{"https://github.com/lodash/lodash/issues/1", "https://example.com/poc"},
		Confidence:  model.ConfidenceMedium,
		SubmittedBy: "triage-agent",
		SubmittedAt: time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC),
	}
}

// utcAdvisory normalises time zones so stores returning local times compare equal.
func utcAdvisory(a model.AgentAdvisory) model.AgentAdvisory {
	a.SubmittedAt = a.SubmittedAt.UTC()
	a.Advisory.Published = a.Advisory.Published.UTC()
	a.Advisory.Modified = a.Advisory.Modified.UTC()
	if a.Advisory.Withdrawn != nil {
		w := a.Advisory.Withdrawn.UTC()
		a.Advisory.Withdrawn = &w
	}
	return a
}

func listAdv(t *testing.T, in store.Intel) []model.AgentAdvisory {
	t.Helper()
	got, err := in.ListAgentAdvisories(context.Background())
	must(t, err)
	return got
}

func testAgentAdvisories(t *testing.T, in store.Intel) {
	ctx := context.Background()
	if got := listAdv(t, in); len(got) != 0 {
		t.Fatalf("empty store: %+v", got)
	}
	b := agentAdvisory("HEIMDALL-AGENT-2")
	a := agentAdvisory("HEIMDALL-AGENT-1")
	a.Advisory.Withdrawn = nil
	a.Confidence = model.ConfidenceHigh
	must(t, in.SaveAgentAdvisory(ctx, b))
	must(t, in.SaveAgentAdvisory(ctx, a))
	want := []model.AgentAdvisory{*agentAdvisory("HEIMDALL-AGENT-1"), *agentAdvisory("HEIMDALL-AGENT-2")}
	want[0].Advisory.Withdrawn, want[0].Confidence = nil, model.ConfidenceHigh

	got := listAdv(t, in)
	if len(got) != 2 {
		t.Fatalf("ListAgentAdvisories = %d records, want 2", len(got))
	}
	for i := range got {
		if g := utcAdvisory(got[i]); !reflect.DeepEqual(g, want[i]) {
			t.Fatalf("advisory %d (ordered by ID, every field round-trips):\n got %+v\nwant %+v", i, g, want[i])
		}
	}

	// Neither the saved input nor a returned value aliases stored state.
	b.Evidence[0] = "MUTATED"
	b.Advisory.Aliases[0] = "MUTATED"
	b.Advisory.References[0] = "MUTATED"
	b.Advisory.Affected[0].Ranges[0].Fixed = "MUTATED"
	b.Advisory.Affected[0].Versions[0] = "MUTATED"
	*b.Advisory.Withdrawn = time.Time{}
	got[1].Evidence[1] = "MUTATED"
	got[1].Advisory.Affected[0].Ranges[1].LastAffected = "MUTATED"
	got[1].Advisory.Sources[0] = "MUTATED"
	if again := listAdv(t, in); !reflect.DeepEqual(utcAdvisory(again[1]), want[1]) {
		t.Fatalf("stored advisory changed through an alias:\n got %+v\nwant %+v", utcAdvisory(again[1]), want[1])
	}

	// Upsert by ID.
	up := agentAdvisory("HEIMDALL-AGENT-2")
	up.Advisory.Summary, up.Advisory.Severity, up.Evidence = "updated", model.SeverityCritical, []string{"https://example.com/new"}
	up.Advisory.Aliases = nil
	must(t, in.SaveAgentAdvisory(ctx, up))
	got = listAdv(t, in)
	if len(got) != 2 || got[1].Advisory.Summary != "updated" || got[1].Advisory.Severity != model.SeverityCritical ||
		!slices.Equal(got[1].Evidence, up.Evidence) || len(got[1].Advisory.Aliases) != 0 || got[0].Advisory.Summary != "prototype pollution" {
		t.Fatalf("upsert by ID: %+v", got)
	}
}

func analysis(eco model.Ecosystem, name, version string, v model.Verdict, at time.Time) *model.LibraryAnalysis {
	return &model.LibraryAnalysis{Ecosystem: eco, Name: name, Version: version, Verdict: v,
		Summary: name + " " + string(v), Evidence: []string{"https://example.com/" + name},
		RecommendedVersion: "9.9.9", Confidence: model.ConfidenceLow, Agent: "analyst", AnalyzedAt: at}
}

func analysisIDs(as []model.LibraryAnalysis) []int64 {
	out := make([]int64, len(as))
	for i, a := range as {
		out[i] = a.ID
	}
	return out
}

func latest(t *testing.T, in store.Intel, f store.AnalysisFilter) []int64 {
	t.Helper()
	got, err := in.LatestAnalyses(context.Background(), f)
	must(t, err)
	return analysisIDs(got)
}

func history(t *testing.T, in store.Intel, eco model.Ecosystem, name string, limit int) []model.LibraryAnalysis {
	t.Helper()
	got, err := in.AnalysisHistory(context.Background(), eco, name, limit)
	must(t, err)
	return got
}

func testAnalyses(t *testing.T, in store.Intel) {
	ctx := context.Background()
	if got := latest(t, in, store.AnalysisFilter{}); len(got) != 0 {
		t.Fatalf("empty store: %v", got)
	}
	if got := history(t, in, model.EcosystemNPM, "lodash", 0); len(got) != 0 {
		t.Fatalf("empty history: %+v", got)
	}
	save := func(a *model.LibraryAnalysis) *model.LibraryAnalysis {
		t.Helper()
		must(t, in.SaveAnalysis(ctx, a))
		return a
	}
	l1 := save(analysis(model.EcosystemNPM, "lodash", "4.17.20", model.VerdictMalicious, t0))
	r1 := save(analysis(model.EcosystemRubyGems, "rails", "", model.VerdictOK, t0))
	g1 := save(analysis(model.EcosystemGo, "golang.org/x/net", "v0.1.0", model.VerdictSafeToBump, t0))
	l2 := save(analysis(model.EcosystemNPM, "lodash", "4.17.21", model.VerdictBreaking, t0.Add(time.Hour)))
	a1 := save(analysis(model.EcosystemNPM, "axios", "1.0.0", model.VerdictAbandoned, t0))
	l3 := save(analysis(model.EcosystemNPM, "lodash", "", model.VerdictOK, t0.Add(2*time.Hour)))
	if l1.ID <= 0 {
		t.Fatalf("SaveAnalysis must set a positive ID: %d", l1.ID)
	}
	for i, ids := 1, []int64{l1.ID, r1.ID, g1.ID, l2.ID, a1.ID, l3.ID}; i < len(ids); i++ {
		if ids[i] <= ids[i-1] {
			t.Fatalf("IDs must increase: %v", ids)
		}
	}

	// Newest per (ecosystem, name), ordered by ecosystem, name.
	if got, want := latest(t, in, store.AnalysisFilter{}), []int64{g1.ID, a1.ID, l3.ID, r1.ID}; !slices.Equal(got, want) {
		t.Fatalf("LatestAnalyses = %v, want %v", got, want)
	}
	if got, want := latest(t, in, store.AnalysisFilter{Ecosystem: model.EcosystemNPM}), []int64{a1.ID, l3.ID}; !slices.Equal(got, want) {
		t.Fatalf("ecosystem filter = %v, want %v", got, want)
	}
	if got, want := latest(t, in, store.AnalysisFilter{Name: "lodash"}), []int64{l3.ID}; !slices.Equal(got, want) {
		t.Fatalf("name filter = %v, want %v", got, want)
	}
	// The verdict filter applies to the latest analysis only: lodash's older
	// "malicious" verdict is superseded.
	if got := latest(t, in, store.AnalysisFilter{Verdict: model.VerdictMalicious}); len(got) != 0 {
		t.Fatalf("verdict filter must apply to the latest analysis: %v", got)
	}
	if got, want := latest(t, in, store.AnalysisFilter{Verdict: model.VerdictOK}), []int64{l3.ID, r1.ID}; !slices.Equal(got, want) {
		t.Fatalf("verdict filter = %v, want %v", got, want)
	}
	if got, want := latest(t, in, store.AnalysisFilter{Limit: 2}), []int64{g1.ID, a1.ID}; !slices.Equal(got, want) {
		t.Fatalf("limit = %v, want %v", got, want)
	}

	// Every field round-trips.
	full, err := in.LatestAnalyses(ctx, store.AnalysisFilter{Ecosystem: model.EcosystemGo, Name: "golang.org/x/net"})
	must(t, err)
	if len(full) != 1 {
		t.Fatalf("LatestAnalyses(go, x/net) = %+v", full)
	}
	g := full[0]
	g.AnalyzedAt = g.AnalyzedAt.UTC()
	if !reflect.DeepEqual(g, *g1) {
		t.Fatalf("analysis round-trip:\n got %+v\nwant %+v", g, *g1)
	}

	// History: newest first, limit.
	h := history(t, in, model.EcosystemNPM, "lodash", 0)
	if got, want := analysisIDs(h), []int64{l3.ID, l2.ID, l1.ID}; !slices.Equal(got, want) {
		t.Fatalf("AnalysisHistory = %v, want %v", got, want)
	}
	if h[2].Verdict != model.VerdictMalicious || h[2].Version != "4.17.20" || !slices.Equal(h[2].Evidence, l1.Evidence) || !h[2].AnalyzedAt.Equal(t0) {
		t.Fatalf("history entry = %+v", h[2])
	}
	if got, want := analysisIDs(history(t, in, model.EcosystemNPM, "lodash", 2)), []int64{l3.ID, l2.ID}; !slices.Equal(got, want) {
		t.Fatalf("history limit = %v, want %v", got, want)
	}
	if got := history(t, in, model.EcosystemGo, "lodash", 0); len(got) != 0 {
		t.Fatalf("history must match the ecosystem too: %+v", got)
	}

	// No aliasing of stored evidence.
	l1.Evidence[0] = "MUTATED"
	h[1].Evidence[0] = "MUTATED"
	h = history(t, in, model.EcosystemNPM, "lodash", 0)
	if h[1].Evidence[0] != "https://example.com/lodash" || h[2].Evidence[0] != "https://example.com/lodash" {
		t.Fatalf("stored analysis changed through an alias: %+v", h)
	}
}

func testIntelConcurrent(t *testing.T, in store.Intel) {
	ctx := context.Background()
	const repos, perRepo, analyses = 8, 200, 40
	items := func(r, round int) []model.InventoryItem {
		out := make([]model.InventoryItem, perRepo)
		for i := range out {
			out[i] = inv("go.mod", model.EcosystemGo, fmt.Sprintf("example.com/r%d/m%03d", r, i), fmt.Sprintf("v%d.0.0", round), true)
		}
		return out
	}
	var wg sync.WaitGroup
	errs := make(chan error, repos*3+analyses)
	for r := range repos {
		repo := fmt.Sprintf("o/r%d", r)
		// Two writers per repo, plus one on a repo shared by everyone: each
		// replace is atomic, so a repo ends with exactly one writer's items.
		for round := range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs <- in.ReplaceInventory(ctx, repo, items(r, round), t0)
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- in.ReplaceInventory(ctx, "o/shared", items(r, 0), t0)
		}()
	}
	saved := make(chan int64, analyses)
	for i := range analyses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a := analysis(model.EcosystemNPM, fmt.Sprintf("lib-%d", i%4), "", model.VerdictOK, t0.Add(time.Duration(i)*time.Second))
			err := in.SaveAnalysis(ctx, a)
			errs <- err
			saved <- a.ID
		}()
	}
	wg.Wait()
	close(errs)
	close(saved)
	for err := range errs {
		must(t, err)
	}
	seen := map[int64]bool{}
	for id := range saved {
		if id <= 0 || seen[id] {
			t.Fatalf("concurrent SaveAnalysis: duplicate or unset ID %d", id)
		}
		seen[id] = true
	}

	for r := range repos {
		got := listInv(t, in, store.InventoryFilter{Repo: fmt.Sprintf("o/r%d", r)})
		if len(got) != perRepo {
			t.Fatalf("repo o/r%d: %d items, want %d", r, len(got), perRepo)
		}
		for _, it := range got {
			if it.Package.Version != got[0].Package.Version {
				t.Fatalf("repo o/r%d mixes two replaces: %s and %s", r, it.Package.Version, got[0].Package.Version)
			}
		}
	}
	shared := listInv(t, in, store.InventoryFilter{Repo: "o/shared"})
	if len(shared) != perRepo {
		t.Fatalf("shared repo: %d items, want %d (one replace must win)", len(shared), perRepo)
	}
	l, err := in.LatestAnalyses(ctx, store.AnalysisFilter{})
	must(t, err)
	if len(l) != 4 {
		t.Fatalf("LatestAnalyses after concurrent saves = %d libraries, want 4", len(l))
	}
	total := 0
	for i := range 4 {
		total += len(history(t, in, model.EcosystemNPM, fmt.Sprintf("lib-%d", i), 0))
	}
	if total != analyses {
		t.Fatalf("history holds %d analyses, want %d", total, analyses)
	}
}
