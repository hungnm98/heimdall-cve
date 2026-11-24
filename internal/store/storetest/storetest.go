// Package storetest is the contract test kit for store.Store. Every store
// implementation must call Run from its tests:
//
//	func TestContract(t *testing.T) { storetest.Run(t, func(t *testing.T) store.Store { return newStore(t) }) }
package storetest

import (
	"context"
	"encoding/base64"
	"errors"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

// Run executes the contract. newStore must return a fresh, empty store.
func Run(t *testing.T, newStore func(t *testing.T) store.Store) {
	t.Helper()
	open := func(t *testing.T) store.Store {
		s := newStore(t)
		ctx := context.Background()
		for i := 0; i < 2; i++ { // Migrate must be idempotent
			if err := s.Migrate(ctx); err != nil {
				t.Fatalf("Migrate #%d: %v", i+1, err)
			}
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	}
	t.Run("Runs", func(t *testing.T) { testRuns(t, open(t)) })
	t.Run("FindingLifecycle", func(t *testing.T) { testLifecycle(t, open(t)) })
	t.Run("DuplicateAndSuppressed", func(t *testing.T) { testDuplicateAndSuppressed(t, open(t)) })
	t.Run("ListFindingsFilter", func(t *testing.T) { testFilter(t, open(t)) })
	t.Run("ListFindingsSort", func(t *testing.T) { testFindingSort(t, open(t)) })
	t.Run("RepoState", func(t *testing.T) { testRepoState(t, open(t)) })
	t.Run("Branches", func(t *testing.T) { testBranches(t, open(t)) })
	t.Run("Snapshots", func(t *testing.T) { testSnapshots(t, open(t)) })
	t.Run("MarkNotified", func(t *testing.T) { testMarkNotified(t, open(t)) })
}

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// F builds a finding for repo/pkg/advisory with its ID computed.
func F(repo, pkg, version, advisory string, sev model.Severity) model.Finding {
	f := model.Finding{
		Kind: model.KindDependency, Provider: "github", Repo: repo, ManifestPath: "go.mod",
		Package: model.NewPackage(model.EcosystemGo, pkg, version), AdvisoryID: advisory, Severity: sev,
		Sources: []string{"osv"},
	}
	f.ComputeID()
	return f
}

func startRun(t *testing.T, s store.Store) *model.ScanRun {
	t.Helper()
	r := &model.ScanRun{StartedAt: t0}
	if err := s.StartRun(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	return r
}

func finishRun(t *testing.T, s store.Store, r *model.ScanRun) {
	t.Helper()
	r.Status, r.FinishedAt = model.RunSucceeded, t0.Add(time.Minute)
	if err := s.FinishRun(context.Background(), r); err != nil {
		t.Fatal(err)
	}
}

func record(t *testing.T, s store.Store, scanned []string, at time.Time, fs ...model.Finding) (*model.ScanRun, *model.Diff) {
	t.Helper()
	r := startRun(t, s)
	d, err := s.RecordFindings(context.Background(), r.ID, scanned, fs, at)
	if err != nil {
		t.Fatal(err)
	}
	finishRun(t, s, r)
	return r, d
}

func ids(fs []model.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID)
	}
	sort.Strings(out)
	return out
}

func wantIDs(t *testing.T, what string, got []model.Finding, want ...model.Finding) {
	t.Helper()
	g, w := ids(got), ids(want)
	if len(g) != len(w) {
		t.Fatalf("%s: got %v, want %v", what, g, w)
	}
	for i := range g {
		if g[i] != w[i] {
			t.Fatalf("%s: got %v, want %v", what, g, w)
		}
	}
}

func testRuns(t *testing.T, s store.Store) {
	ctx := context.Background()
	if _, err := s.LatestRun(ctx, 0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("LatestRun on empty store: %v, want ErrNotFound", err)
	}
	r1 := startRun(t, s)
	r2 := startRun(t, s)
	if r1.ID <= 0 || r2.ID <= r1.ID {
		t.Fatalf("run IDs must be positive and increasing: %d, %d", r1.ID, r2.ID)
	}
	if got, err := s.GetRun(ctx, r1.ID); err != nil || got.Status != model.RunRunning {
		t.Fatalf("GetRun: %+v %v", got, err)
	}
	if _, err := s.LatestRun(ctx, 0); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("LatestRun must ignore running runs")
	}
	r1.ReposScanned = []string{"o/a"}
	r1.Stats = model.RunStats{OpenBySeverity: map[model.Severity]int{model.SeverityHigh: 3}, New: 2, Fixed: 1, Repos: 1}
	finishRun(t, s, r1)
	finishRun(t, s, r2)
	if got, _ := s.LatestRun(ctx, 0); got == nil || got.ID != r2.ID {
		t.Fatalf("LatestRun(0) = %+v, want run %d", got, r2.ID)
	}
	if got, _ := s.LatestRun(ctx, r2.ID); got == nil || got.ID != r1.ID || len(got.ReposScanned) != 1 ||
		got.Stats.OpenBySeverity[model.SeverityHigh] != 3 || got.Stats.New != 2 {
		t.Fatalf("LatestRun(before r2) = %+v, want run %d with repos and stats", got, r1.ID)
	}
	if runs, _ := s.ListRuns(ctx, 1); len(runs) != 1 || runs[0].ID != r2.ID {
		t.Fatalf("ListRuns(1) = %+v", runs)
	}
	if _, err := s.GetRun(ctx, 9999); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetRun(missing): %v", err)
	}
}

func testLifecycle(t *testing.T, s store.Store) {
	ctx := context.Background()
	a := F("o/r1", "example.com/a", "v1.0.0", "GO-1", model.SeverityHigh)
	b := F("o/r1", "example.com/b", "v1.0.0", "GO-2", model.SeverityLow)
	c := F("o/r1", "example.com/c", "v1.0.0", "GO-3", model.SeverityCritical)
	x := F("o/r2", "example.com/x", "v1.0.0", "GO-4", model.SeverityMedium)
	t1, t2, t3, t4 := t0, t0.Add(24*time.Hour), t0.Add(48*time.Hour), t0.Add(72*time.Hour)

	run1, d1 := record(t, s, []string{"o/r1", "o/r2"}, t1, a, b, x)
	wantIDs(t, "run1 new", d1.New, a, b, x)

	aBumped := F("o/r1", "example.com/a", "v1.0.1", "GO-1", model.SeverityHigh) // still vulnerable
	run2, d2 := record(t, s, []string{"o/r1", "o/r2"}, t2, aBumped, c, x)
	wantIDs(t, "run2 new", d2.New, c)
	wantIDs(t, "run2 fixed", d2.Fixed, b)
	wantIDs(t, "run2 still open", d2.StillOpen, aBumped, x)
	if d2.FromRun != run1.ID || d2.ToRun != run2.ID {
		t.Fatalf("diff runs = %d→%d, want %d→%d", d2.FromRun, d2.ToRun, run1.ID, run2.ID)
	}
	got, err := s.GetFinding(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.FirstSeen.Equal(t1) || !got.LastSeen.Equal(t2) || got.Package.Version != "v1.0.1" || got.Status != model.StatusOpen {
		t.Fatalf("bumped finding: first=%v last=%v version=%s status=%s", got.FirstSeen, got.LastSeen, got.Package.Version, got.Status)
	}
	if got, _ := s.GetFinding(ctx, b.ID); got.Status != model.StatusFixed {
		t.Fatalf("b status = %s, want fixed", got.Status)
	}

	// A run that only scanned o/r2 must not mark o/r1 findings fixed.
	_, d3 := record(t, s, []string{"o/r2"}, t3, x)
	if len(d3.Fixed) != 0 {
		t.Fatalf("run3 fixed %v; repos outside scope must be untouched", ids(d3.Fixed))
	}
	if got, _ := s.GetFinding(ctx, c.ID); got.Status != model.StatusOpen {
		t.Fatalf("c status = %s, want open", got.Status)
	}

	// b comes back: reopened counts as new.
	_, d4 := record(t, s, []string{"o/r1"}, t4, aBumped, b, c)
	wantIDs(t, "run4 new (reopened)", d4.New, b)
	if got, _ := s.GetFinding(ctx, b.ID); !got.FirstSeen.Equal(t1) || got.Status != model.StatusOpen {
		t.Fatalf("reopened b: first=%v status=%s", got.FirstSeen, got.Status)
	}

	dr, err := s.DiffRuns(ctx, run1.ID, run2.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantIDs(t, "DiffRuns new", dr.New, c)
	wantIDs(t, "DiffRuns fixed", dr.Fixed, b)
	wantIDs(t, "DiffRuns still open", dr.StillOpen, aBumped, x)
	if _, err := s.GetFinding(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetFinding(missing): %v", err)
	}
}

func testDuplicateAndSuppressed(t *testing.T, s store.Store) {
	ctx := context.Background()
	a := F("o/r", "example.com/a", "v1.0.0", "GO-1", model.SeverityHigh)
	dup := a
	dup.Sources = []string{"osv", "agent"}
	_, d := record(t, s, []string{"o/r"}, t0, a, dup)
	if len(d.New) != 1 {
		t.Fatalf("duplicate IDs must be stored once, new = %v", ids(d.New))
	}
	if all, _ := s.ListFindings(ctx, store.FindingFilter{}); len(all) != 1 {
		t.Fatalf("stored %d findings, want 1", len(all))
	}
	if err := s.SetFindingStatus(ctx, a.ID, model.StatusSuppressed); err != nil {
		t.Fatal(err)
	}
	_, d2 := record(t, s, []string{"o/r"}, t0.Add(time.Hour), a)
	if len(d2.New)+len(d2.StillOpen)+len(d2.Fixed) != 0 {
		t.Fatalf("suppressed finding must not appear in diff: %+v", d2)
	}
	if got, _ := s.GetFinding(ctx, a.ID); got.Status != model.StatusSuppressed {
		t.Fatalf("status = %s, want suppressed", got.Status)
	}
}

func testFilter(t *testing.T, s store.Store) {
	ctx := context.Background()
	hi := F("o/r1", "example.com/a", "v1", "GO-1", model.SeverityHigh)
	hi.InKEV = true
	lo := F("o/r2", "example.com/b", "v1", "GO-2", model.SeverityLow)
	record(t, s, []string{"o/r1", "o/r2"}, t0, hi, lo)
	crit := F("o/r1", "example.com/c", "v1", "GO-3", model.SeverityCritical)
	record(t, s, []string{"o/r1", "o/r2"}, t0.Add(time.Hour), hi, lo, crit)

	cases := []struct {
		name string
		f    store.FindingFilter
		want []model.Finding
	}{
		{"all", store.FindingFilter{}, []model.Finding{hi, lo, crit}},
		{"repo", store.FindingFilter{Repo: "o/r2"}, []model.Finding{lo}},
		{"min severity", store.FindingFilter{MinSeverity: model.SeverityHigh}, []model.Finding{hi, crit}},
		{"kev", store.FindingFilter{InKEV: true}, []model.Finding{hi}},
		{"new since", store.FindingFilter{NewSince: t0.Add(time.Minute)}, []model.Finding{crit}},
		{"status", store.FindingFilter{Status: model.StatusFixed}, nil},
	}
	for _, c := range cases {
		got, err := s.ListFindings(ctx, c.f)
		if err != nil {
			t.Fatal(err)
		}
		wantIDs(t, c.name, got, c.want...)
	}
	got, _ := s.ListFindings(ctx, store.FindingFilter{Limit: 1})
	if len(got) != 1 || got[0].ID != crit.ID {
		t.Fatalf("Limit 1 must return the most severe first, got %v", ids(got))
	}

	// Keyset pagination walks every finding once, in order.
	var pages []string
	after := ""
	for i := 0; i < 10; i++ {
		page, err := s.ListFindings(ctx, store.FindingFilter{Limit: 1, After: after})
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		pages = append(pages, page[0].ID)
		after = store.FindingCursor(page[0], store.FindingFilter{})
	}
	if len(pages) != 3 || pages[0] != crit.ID || pages[1] != hi.ID || pages[2] != lo.ID {
		t.Fatalf("pagination = %v, want [crit hi lo]", pages)
	}
	if _, err := s.ListFindings(ctx, store.FindingFilter{After: "%%%"}); err == nil {
		t.Fatal("invalid cursor must fail")
	}

	// Search by package substring and by alias.
	aliased := F("o/r1", "github.com/Acme/Widget", "v1", "GO-9", model.SeverityLow)
	aliased.Aliases = []string{"CVE-2024-0001"}
	record(t, s, []string{"o/r1", "o/r2"}, t0.Add(2*time.Hour), hi, lo, crit, aliased)
	for _, q := range []string{"acme/widget", "CVE-2024-0001", "GO-9"} {
		got, err := s.ListFindings(ctx, store.FindingFilter{Query: q})
		if err != nil {
			t.Fatal(err)
		}
		wantIDs(t, "query "+q, got, aliased)
	}
}

func testFindingSort(t *testing.T, s store.Store) {
	ctx := context.Background()
	a := F("o/b", "Zeta", "v1", "GO-1", model.SeverityHigh)
	a.Priority = 50
	b := F("o/a", "alpha", "v1", "GO-2", model.SeverityHigh)
	b.Priority = 90
	c := model.Finding{ // runtime: no package, named after the runtime
		Kind: model.KindRuntime, Provider: "github", Repo: "o/c", ManifestPath: ".nvmrc", AdvisoryID: "EOL-NODE-16",
		Severity: model.SeverityCritical, Priority: 50, Runtime: &model.RuntimeStatus{Runtime: model.Runtime{Name: "node", Version: "16"}},
	}
	c.ComputeID()
	d := model.Finding{ // no package, no runtime: named after the advisory
		Kind: model.KindSecret, Provider: "github", Repo: "o/a", ManifestPath: "config.yml", AdvisoryID: "GHSA-XXXX",
		Severity: model.SeverityLow, Priority: 10,
	}
	d.ComputeID()
	e := F("o/b", "beta", "v1", "GO-3", model.SeverityHigh)
	e.Priority = 70
	repos := []string{"o/a", "o/b", "o/c"}
	record(t, s, repos, t0, a, b)
	record(t, s, repos, t0.Add(time.Hour), a, b, c, d)
	record(t, s, repos, t0.Add(2*time.Hour), a, b, c, d, e)

	// byID orders findings that tie on the sort key by ID (desc when reverse).
	byID := func(reverse bool, fs ...model.Finding) []model.Finding {
		sort.Slice(fs, func(i, j int) bool { return (fs[i].ID < fs[j].ID) != reverse })
		return fs
	}
	cat := func(parts ...[]model.Finding) []model.Finding {
		var out []model.Finding
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	one := func(f model.Finding) []model.Finding { return []model.Finding{f} }
	rev := func(fs []model.Finding) []model.Finding {
		out := make([]model.Finding, len(fs))
		for i, f := range fs {
			out[len(fs)-1-i] = f
		}
		return out
	}

	sevDesc := cat(one(c), one(b), byID(false, a, e), one(d)) // rank desc, repo asc, id asc
	prioDesc := cat(one(b), one(e), byID(true, a, c), one(d))
	nameAsc := []model.Finding{b, e, d, c, a} // alpha, beta, ghsa-xxxx, node, zeta
	firstDesc := cat(one(e), byID(true, c, d), byID(true, a, b))
	repoAsc := cat(byID(false, b, d), byID(false, a, e), one(c))
	cases := []struct {
		sort  store.FindingSort
		order store.SortOrder
		want  []model.Finding
	}{
		{"", "", sevDesc},
		{store.SortSeverity, store.OrderDesc, sevDesc},
		{store.SortSeverity, store.OrderAsc, rev(sevDesc)},
		{store.SortPriority, "", prioDesc},
		{store.SortPriority, store.OrderAsc, rev(prioDesc)},
		{store.SortName, "", nameAsc},
		{store.SortName, store.OrderDesc, rev(nameAsc)},
		{store.SortFirstSeen, store.OrderDesc, firstDesc},
		{store.SortFirstSeen, store.OrderAsc, rev(firstDesc)},
		{store.SortRepo, store.OrderAsc, repoAsc},
		{store.SortRepo, store.OrderDesc, rev(repoAsc)},
	}
	for _, tc := range cases {
		name := string(tc.sort) + " " + string(tc.order)
		flt := store.FindingFilter{Sort: tc.sort, Order: tc.order}
		all, err := s.ListFindings(ctx, flt)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		wantOrder(t, name, all, tc.want)
		// Keyset pagination across pages of 2 yields the same order.
		var paged []model.Finding
		for i := 0; i < 10; i++ {
			flt.Limit = 2
			page, err := s.ListFindings(ctx, flt)
			if err != nil {
				t.Fatalf("%s page %d: %v", name, i, err)
			}
			paged = append(paged, page...)
			if len(page) < 2 {
				break
			}
			flt.After = store.FindingCursor(page[len(page)-1], flt)
		}
		wantOrder(t, name+" paged", paged, tc.want)
	}

	// A cursor only works for the sort and order that issued it.
	cur := store.FindingCursor(b, store.FindingFilter{Sort: store.SortPriority})
	for _, flt := range []store.FindingFilter{
		{Sort: store.SortName, After: cur},
		{Sort: store.SortPriority, Order: store.OrderAsc, After: cur},
		{After: base64.RawURLEncoding.EncodeToString([]byte("3\x00o/a\x00" + b.ID))}, // pre-sort format
	} {
		if _, err := s.ListFindings(ctx, flt); !errors.Is(err, store.ErrStaleCursor) {
			t.Fatalf("mismatched cursor %+v: err = %v, want ErrStaleCursor", flt, err)
		}
	}
	for _, flt := range []store.FindingFilter{{Sort: "cvss"}, {Order: "up"}} {
		if _, err := s.ListFindings(ctx, flt); err == nil {
			t.Fatalf("invalid sort %+v must fail", flt)
		}
	}
}

func wantOrder(t *testing.T, what string, got, want []model.Finding) {
	t.Helper()
	g, w := make([]string, len(got)), make([]string, len(want))
	for i := range got {
		g[i] = got[i].ID
	}
	for i := range want {
		w[i] = want[i].ID
	}
	if strings.Join(g, ",") != strings.Join(w, ",") {
		t.Fatalf("%s: got %v, want %v", what, g, w)
	}
}

func testRepoState(t *testing.T, s store.Store) {
	ctx := context.Background()
	if _, err := s.GetRepoState(ctx, "o/r", "main"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing state: %v", err)
	}
	st := model.RepoState{Repo: "o/r", Ref: "main", HeadSHA: "abc", ScannedAt: t0}
	if err := s.PutRepoState(ctx, st); err != nil {
		t.Fatal(err)
	}
	st.HeadSHA = "def"
	if err := s.PutRepoState(ctx, st); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetRepoState(ctx, "o/r", "main")
	if err != nil || got.HeadSHA != "def" {
		t.Fatalf("GetRepoState = %+v, %v", got, err)
	}
	if _, err := s.GetRepoState(ctx, "o/r", "develop"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("state must be per ref")
	}
}

func testMarkNotified(t *testing.T, s store.Store) {
	ctx := context.Background()
	var firsts atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			first, err := s.MarkNotified(ctx, "finding.new:abc", t0)
			if err != nil {
				t.Error(err)
			}
			if first {
				firsts.Add(1)
			}
		}()
	}
	wg.Wait()
	if firsts.Load() != 1 {
		t.Fatalf("MarkNotified returned true %d times, want exactly 1", firsts.Load())
	}
}

// onBranch returns f on an extra branch (its ID recomputed).
func onBranch(f model.Finding, branch string) model.Finding {
	f.Branch = branch
	f.ComputeID()
	return f
}

func testBranches(t *testing.T, s store.Store) {
	ctx := context.Background()
	main := F("acme/api", "golang.org/x/net", "0.1.0", "GO-2024-0001", model.SeverityHigh)
	dev := onBranch(main, "develop")
	rel := onBranch(main, "release/1")
	if main.ID == dev.ID || dev.ID == rel.ID {
		t.Fatal("a branch must change the finding ID")
	}
	base := main
	base.Branch = ""
	if base.ComputeID() != main.ID {
		t.Fatal("primary-branch IDs must not depend on branches")
	}
	_, d := record(t, s, []string{"acme/api", "acme/api@develop", "acme/api@release/1"}, t0, main, dev, rel)
	wantIDs(t, "new", d.New, main, dev, rel)

	// Scanning only develop (fixed there) leaves the other branches alone.
	_, d = record(t, s, []string{"acme/api@develop"}, t0.Add(time.Hour))
	wantIDs(t, "fixed on develop", d.Fixed, dev)

	got, err := s.ListFindings(ctx, store.FindingFilter{Status: model.StatusOpen, DefaultBranchOnly: true})
	must(t, err)
	wantIDs(t, "primary only", got, main)
	got, err = s.ListFindings(ctx, store.FindingFilter{Status: model.StatusOpen, Branch: "release/1"})
	must(t, err)
	wantIDs(t, "release/1", got, rel)

	gone, err := s.MarkBranchesRemoved(ctx, "acme/api", []string{"develop"})
	must(t, err)
	wantIDs(t, "removed", gone, rel)
	if f, _ := s.GetFinding(ctx, rel.ID); f.Status != model.StatusRemoved {
		t.Fatalf("status = %s, want removed", f.Status)
	}
	if f, _ := s.GetFinding(ctx, main.ID); f.Status != model.StatusOpen {
		t.Fatal("the primary branch is never removed")
	}
	// The branch comes back: its finding reopens as new.
	_, d = record(t, s, []string{"acme/api@release/1"}, t0.Add(2*time.Hour), rel)
	wantIDs(t, "reopened", d.New, rel)

	must(t, s.PutRepoState(ctx, model.RepoState{Repo: "acme/api", Ref: "main", HeadSHA: "a", ScannedAt: t0}))
	must(t, s.PutRepoState(ctx, model.RepoState{Repo: "acme/api", Ref: "develop", HeadSHA: "b", ScannedAt: t0}))
	must(t, s.PutRepoState(ctx, model.RepoState{Repo: "acme/other", Ref: "main", HeadSHA: "c", ScannedAt: t0}))
	states, err := s.ListRepoStates(ctx, "acme/api")
	must(t, err)
	if len(states) != 2 || states[0].Ref != "develop" || states[1].Ref != "main" || states[1].HeadSHA != "a" {
		t.Fatalf("ListRepoStates = %+v", states)
	}
}

func testSnapshots(t *testing.T, s store.Store) {
	ss, ok := s.(store.Snapshots)
	if !ok {
		t.Skip("store does not cache commit snapshots")
	}
	ctx := context.Background()
	if _, err := ss.GetSnapshot(ctx, "acme/api", "sha1", "fp", t0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("miss: %v", err)
	}
	must(t, ss.PutSnapshot(ctx, "acme/api", "sha1", "fp", []byte("one"), t0, t0.Add(-time.Hour)))
	if b, err := ss.GetSnapshot(ctx, "acme/api", "sha1", "fp", t0.Add(time.Hour)); err != nil || string(b) != "one" {
		t.Fatalf("hit: %q %v", b, err)
	}
	if _, err := ss.GetSnapshot(ctx, "acme/api", "sha1", "other-fp", t0); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a different fingerprint must miss")
	}
	// sha1 was used at t0+1h; pruning before t0+2h removes it.
	must(t, ss.PutSnapshot(ctx, "acme/api", "sha2", "fp", []byte("two"), t0.Add(3*time.Hour), t0.Add(2*time.Hour)))
	if _, err := ss.GetSnapshot(ctx, "acme/api", "sha1", "fp", t0); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("unused snapshots must be pruned")
	}
}
