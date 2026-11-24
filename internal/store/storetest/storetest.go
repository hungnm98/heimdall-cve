// Package storetest is the contract test kit for store.Store. Every store
// implementation must call Run from its tests:
//
//	func TestContract(t *testing.T) { storetest.Run(t, func(t *testing.T) store.Store { return newStore(t) }) }
package storetest

import (
	"context"
	"errors"
	"sort"
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
	t.Run("RepoState", func(t *testing.T) { testRepoState(t, open(t)) })
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
	finishRun(t, s, r1)
	finishRun(t, s, r2)
	if got, _ := s.LatestRun(ctx, 0); got == nil || got.ID != r2.ID {
		t.Fatalf("LatestRun(0) = %+v, want run %d", got, r2.ID)
	}
	if got, _ := s.LatestRun(ctx, r2.ID); got == nil || got.ID != r1.ID || len(got.ReposScanned) != 1 {
		t.Fatalf("LatestRun(before r2) = %+v, want run %d with repos", got, r1.ID)
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
