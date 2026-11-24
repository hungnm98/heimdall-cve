// Package memstore is an in-memory store.Store. It is the reference
// implementation of the store contract and is used by tests of other
// packages; state is lost when the process exits.
package memstore

import (
	"context"
	"fmt"
	"maps"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

func init() {
	store.Registry.Register("memory", func(plugin.Config, plugin.Deps) (store.Store, error) { return New(), nil })
}

// Store is safe for concurrent use.
type Store struct {
	mu         sync.Mutex
	nextID     int64
	runs       map[int64]model.ScanRun
	findings   map[string]model.Finding
	snapshots  map[int64]map[string]model.Finding // findings recorded per run (non-suppressed)
	scanned    map[int64]map[string]bool          // scopes scanned per run
	repoStates map[string]model.RepoState
	notified   map[string]time.Time
	commits    map[string]commitSnapshot // store.Snapshots: repo\x00sha\x00fingerprint
	cat        catalog                   // store.Catalog state (catalog.go)
	intel      intel                     // store.Intel state (intel.go)
}

var (
	_ store.Store     = (*Store)(nil)
	_ store.Snapshots = (*Store)(nil)
)

type commitSnapshot struct {
	data []byte
	used time.Time
}

// New returns an empty store.
func New() *Store {
	return &Store{
		runs:       map[int64]model.ScanRun{},
		findings:   map[string]model.Finding{},
		snapshots:  map[int64]map[string]model.Finding{},
		scanned:    map[int64]map[string]bool{},
		repoStates: map[string]model.RepoState{},
		notified:   map[string]time.Time{},
		commits:    map[string]commitSnapshot{},
	}
}

func (s *Store) Migrate(context.Context) error { return nil }
func (s *Store) Close() error                  { return nil }

func (s *Store) StartRun(_ context.Context, run *model.ScanRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	run.ID = s.nextID
	run.Status = model.RunRunning
	s.runs[run.ID] = cloneRun(*run)
	return nil
}

func (s *Store) FinishRun(_ context.Context, run *model.ScanRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.runs[run.ID]; !ok {
		return fmt.Errorf("run %d: %w", run.ID, store.ErrNotFound)
	}
	s.runs[run.ID] = cloneRun(*run)
	return nil
}

func (s *Store) GetRun(_ context.Context, id int64) (*model.ScanRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.runs[id]
	if !ok {
		return nil, fmt.Errorf("run %d: %w", id, store.ErrNotFound)
	}
	r = cloneRun(r)
	return &r, nil
}

func (s *Store) LatestRun(_ context.Context, before int64) (*model.ScanRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var best *model.ScanRun
	for _, r := range s.runs {
		if r.Status == model.RunRunning || (before > 0 && r.ID >= before) {
			continue
		}
		if best == nil || r.ID > best.ID {
			r := cloneRun(r)
			best = &r
		}
	}
	if best == nil {
		return nil, fmt.Errorf("latest run: %w", store.ErrNotFound)
	}
	return best, nil
}

func (s *Store) ListRuns(_ context.Context, limit int) ([]model.ScanRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.ScanRun, 0, len(s.runs))
	for _, r := range s.runs {
		out = append(out, cloneRun(r))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) RecordFindings(_ context.Context, runID int64, scanned []string, findings []model.Finding, at time.Time) (*model.Diff, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.runs[runID]; !ok {
		return nil, fmt.Errorf("run %d: %w", runID, store.ErrNotFound)
	}
	diff := &model.Diff{ToRun: runID}
	for id := range s.runs {
		if id < runID && id > diff.FromRun && s.runs[id].Status != model.RunRunning {
			diff.FromRun = id
		}
	}

	incoming := map[string]model.Finding{}
	for _, f := range findings {
		incoming[f.ID] = f
	}
	scope := map[string]bool{}
	for _, r := range scanned {
		scope[r] = true
	}
	snap := s.snapshots[runID]
	if snap == nil {
		snap = map[string]model.Finding{}
		s.snapshots[runID] = snap
	}
	if s.scanned[runID] == nil {
		s.scanned[runID] = map[string]bool{}
	}
	for r := range scope {
		s.scanned[runID][r] = true
	}

	for _, id := range sortedIDs(incoming) {
		f := incoming[id]
		f.LastSeen = at
		prev, seen := s.findings[id]
		switch {
		case !seen:
			f.FirstSeen, f.Status = at, model.StatusOpen
			diff.New = append(diff.New, f)
		case prev.Status == model.StatusSuppressed:
			f.FirstSeen, f.Status = prev.FirstSeen, model.StatusSuppressed
		case prev.Status == model.StatusFixed, prev.Status == model.StatusRemoved:
			f.FirstSeen, f.Status = prev.FirstSeen, model.StatusOpen
			diff.New = append(diff.New, f)
		default:
			f.FirstSeen, f.Status = prev.FirstSeen, model.StatusOpen
			diff.StillOpen = append(diff.StillOpen, f)
		}
		s.findings[id] = f
		if f.Status != model.StatusSuppressed {
			snap[id] = f
		}
	}
	for _, id := range sortedIDs(s.findings) {
		f := s.findings[id]
		if f.Status != model.StatusOpen || !scope[f.ScopeKey()] {
			continue
		}
		if _, ok := incoming[id]; ok {
			continue
		}
		f.Status = model.StatusFixed
		s.findings[id] = f
		diff.Fixed = append(diff.Fixed, f)
	}
	return diff, nil
}

func (s *Store) ListFindings(_ context.Context, flt store.FindingFilter) ([]model.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sortKey, order, err := store.ResolveFindingSort(flt.Sort, flt.Order)
	if err != nil {
		return nil, err
	}
	var cur *store.FindingKey
	if flt.After != "" {
		k, err := store.ParseFindingCursor(flt)
		if err != nil {
			return nil, err
		}
		cur = &k
	}
	var out []model.Finding
	for _, f := range s.findings {
		if match(f, flt) && (cur == nil || store.KeyOf(f, sortKey, order).Compare(*cur) > 0) {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return store.KeyOf(out[i], sortKey, order).Compare(store.KeyOf(out[j], sortKey, order)) < 0
	})
	if flt.Limit > 0 && len(out) > flt.Limit {
		out = out[:flt.Limit]
	}
	return out, nil
}

func match(f model.Finding, flt store.FindingFilter) bool {
	switch {
	case flt.Repo != "" && f.Repo != flt.Repo,
		flt.Kind != "" && f.Kind != flt.Kind,
		flt.Status != "" && f.Status != flt.Status,
		flt.MinSeverity != "" && !f.Severity.AtLeast(flt.MinSeverity),
		flt.InKEV && !f.InKEV,
		flt.Branch != "" && f.Branch != flt.Branch,
		flt.DefaultBranchOnly && f.Branch != "",
		!flt.NewSince.IsZero() && f.FirstSeen.Before(flt.NewSince),
		flt.Query != "" && !matchQuery(f, flt.Query):
		return false
	}
	return true
}

func matchQuery(f model.Finding, q string) bool {
	if strings.Contains(strings.ToLower(f.Package.Name), strings.ToLower(q)) || f.AdvisoryID == q {
		return true
	}
	for _, a := range f.Aliases {
		if a == q {
			return true
		}
	}
	return false
}

func (s *Store) GetFinding(_ context.Context, id string) (*model.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.findings[id]
	if !ok {
		return nil, fmt.Errorf("finding %s: %w", id, store.ErrNotFound)
	}
	return &f, nil
}

func (s *Store) SetFindingStatus(_ context.Context, id string, status model.FindingStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.findings[id]
	if !ok {
		return fmt.Errorf("finding %s: %w", id, store.ErrNotFound)
	}
	f.Status = status
	s.findings[id] = f
	return nil
}

func (s *Store) DiffRuns(_ context.Context, from, to int64) (*model.Diff, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range []int64{from, to} {
		if _, ok := s.runs[id]; !ok {
			return nil, fmt.Errorf("run %d: %w", id, store.ErrNotFound)
		}
	}
	a, b := s.snapshots[from], s.snapshots[to]
	d := &model.Diff{FromRun: from, ToRun: to}
	for _, id := range sortedIDs(b) {
		if _, ok := a[id]; ok {
			d.StillOpen = append(d.StillOpen, b[id])
		} else {
			d.New = append(d.New, b[id])
		}
	}
	for _, id := range sortedIDs(a) {
		f := a[id]
		if _, ok := b[id]; !ok && s.scanned[to][f.ScopeKey()] {
			d.Fixed = append(d.Fixed, f)
		}
	}
	return d, nil
}

func (s *Store) GetRepoState(_ context.Context, repo, ref string) (*model.RepoState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repoStates[repo+"\x00"+ref]
	if !ok {
		return nil, fmt.Errorf("repo state %s@%s: %w", repo, ref, store.ErrNotFound)
	}
	return &st, nil
}

func (s *Store) PutRepoState(_ context.Context, st model.RepoState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.repoStates[st.Repo+"\x00"+st.Ref] = st
	return nil
}

func (s *Store) ListRepoStates(_ context.Context, repo string) ([]model.RepoState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []model.RepoState
	for _, st := range s.repoStates {
		if st.Repo == repo {
			out = append(out, st)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out, nil
}

func (s *Store) MarkBranchesRemoved(_ context.Context, repo string, keep []string) ([]model.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := map[string]bool{}
	for _, b := range keep {
		kept[b] = true
	}
	var out []model.Finding
	for _, id := range sortedIDs(s.findings) {
		f := s.findings[id]
		if f.Repo != repo || f.Branch == "" || kept[f.Branch] || f.Status != model.StatusOpen {
			continue
		}
		f.Status = model.StatusRemoved
		s.findings[id] = f
		out = append(out, f)
	}
	return out, nil
}

func commitKey(repo, sha, fp string) string { return repo + "\x00" + sha + "\x00" + fp }

func (s *Store) GetSnapshot(_ context.Context, repo, sha, fp string, at time.Time) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.commits[commitKey(repo, sha, fp)]
	if !ok {
		return nil, fmt.Errorf("snapshot %s@%s: %w", repo, sha, store.ErrNotFound)
	}
	c.used = at
	s.commits[commitKey(repo, sha, fp)] = c
	return append([]byte(nil), c.data...), nil
}

func (s *Store) PutSnapshot(_ context.Context, repo, sha, fp string, data []byte, at, pruneBefore time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, c := range s.commits {
		if c.used.Before(pruneBefore) {
			delete(s.commits, k)
		}
	}
	s.commits[commitKey(repo, sha, fp)] = commitSnapshot{data: append([]byte(nil), data...), used: at}
	return nil
}

func (s *Store) MarkNotified(_ context.Context, key string, at time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.notified[key]; ok {
		return false, nil
	}
	s.notified[key] = at
	return true, nil
}

func cloneRun(r model.ScanRun) model.ScanRun {
	r.Targets = append([]string(nil), r.Targets...)
	r.ReposScanned = append([]string(nil), r.ReposScanned...)
	r.ReposFailed = append([]string(nil), r.ReposFailed...)
	r.Sources = append([]model.SourceHealth(nil), r.Sources...)
	r.Stats.OpenBySeverity = maps.Clone(r.Stats.OpenBySeverity)
	return r
}

func sortedIDs(m map[string]model.Finding) []string {
	out := make([]string, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
