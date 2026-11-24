package memstore

import (
	"context"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

var _ store.Intel = (*Store)(nil)

// intel is the in-memory store.Intel state.
type intel struct {
	mu        sync.Mutex
	inventory map[string][]model.InventoryItem // repo → items
	agentAdvs map[string]model.AgentAdvisory   // advisory id → record
	analyses  []model.LibraryAnalysis          // append-only history
	seq       int64
}

func (s *Store) ReplaceInventory(_ context.Context, repo string, items []model.InventoryItem, _ time.Time) error {
	in := &s.intel
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.inventory == nil {
		in.inventory = map[string][]model.InventoryItem{}
	}
	cp := make([]model.InventoryItem, len(items))
	for i, it := range items {
		it.Repo = repo
		cp[i] = it
	}
	sortInventory(cp)
	in.inventory[repo] = cp
	return nil
}

func sortInventory(items []model.InventoryItem) {
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i], items[j]
		switch {
		case a.Repo != b.Repo:
			return a.Repo < b.Repo
		case a.ManifestPath != b.ManifestPath:
			return a.ManifestPath < b.ManifestPath
		case a.Package.Ecosystem != b.Package.Ecosystem:
			return a.Package.Ecosystem < b.Package.Ecosystem
		case a.Package.Name != b.Package.Name:
			return a.Package.Name < b.Package.Name
		}
		return a.Package.Version < b.Package.Version
	})
}

func (s *Store) ListInventory(_ context.Context, f store.InventoryFilter) ([]model.InventoryItem, error) {
	in := &s.intel
	in.mu.Lock()
	defer in.mu.Unlock()
	var out []model.InventoryItem
	for repo, items := range in.inventory {
		if f.Repo != "" && repo != f.Repo {
			continue
		}
		for _, it := range items {
			if (f.Ecosystem == "" || it.Package.Ecosystem == f.Ecosystem) &&
				(f.Name == "" || it.Package.Name == f.Name) && (!f.DirectOnly || it.Direct) {
				out = append(out, it)
			}
		}
	}
	sortInventory(out)
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

func (s *Store) PackageUsage(_ context.Context, f store.UsageFilter) ([]model.PackageUsage, error) {
	in := &s.intel
	in.mu.Lock()
	defer in.mu.Unlock()
	type acc struct {
		u        model.PackageUsage
		versions map[string]bool
		repos    map[string]bool
	}
	by := map[[2]string]*acc{}
	for repo, items := range in.inventory {
		for _, it := range items {
			if it.Private || it.Unresolvable != "" || (f.Ecosystem != "" && it.Package.Ecosystem != f.Ecosystem) {
				continue
			}
			k := [2]string{string(it.Package.Ecosystem), it.Package.Name}
			a := by[k]
			if a == nil {
				a = &acc{u: model.PackageUsage{Ecosystem: it.Package.Ecosystem, Name: it.Package.Name}, versions: map[string]bool{}, repos: map[string]bool{}}
				by[k] = a
			}
			a.versions[it.Package.Version] = true
			a.repos[repo] = true
			a.u.Direct = a.u.Direct || it.Direct
		}
	}
	var out []model.PackageUsage
	for _, a := range by {
		if f.DirectOnly && !a.u.Direct {
			continue
		}
		a.u.Versions = sortedKeys(a.versions)
		a.u.Repos = sortedKeys(a.repos)
		out = append(out, a.u)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case len(a.Repos) != len(b.Repos):
			return len(a.Repos) > len(b.Repos)
		case a.Ecosystem != b.Ecosystem:
			return a.Ecosystem < b.Ecosystem
		}
		return a.Name < b.Name
	})
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (s *Store) SaveAgentAdvisory(_ context.Context, a *model.AgentAdvisory) error {
	in := &s.intel
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.agentAdvs == nil {
		in.agentAdvs = map[string]model.AgentAdvisory{}
	}
	cp := *a
	cp.Evidence = slices.Clone(a.Evidence)
	cp.Advisory.Aliases = slices.Clone(a.Advisory.Aliases)
	cp.Advisory.Affected = slices.Clone(a.Advisory.Affected)
	in.agentAdvs[a.Advisory.ID] = cp
	return nil
}

func (s *Store) ListAgentAdvisories(context.Context) ([]model.AgentAdvisory, error) {
	in := &s.intel
	in.mu.Lock()
	defer in.mu.Unlock()
	out := make([]model.AgentAdvisory, 0, len(in.agentAdvs))
	for _, a := range in.agentAdvs {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Advisory.ID < out[j].Advisory.ID })
	return out, nil
}

func (s *Store) SaveAnalysis(_ context.Context, a *model.LibraryAnalysis) error {
	in := &s.intel
	in.mu.Lock()
	defer in.mu.Unlock()
	in.seq++
	a.ID = in.seq
	cp := *a
	cp.Evidence = slices.Clone(a.Evidence)
	in.analyses = append(in.analyses, cp)
	return nil
}

func (s *Store) LatestAnalyses(_ context.Context, f store.AnalysisFilter) ([]model.LibraryAnalysis, error) {
	in := &s.intel
	in.mu.Lock()
	defer in.mu.Unlock()
	latest := map[[2]string]model.LibraryAnalysis{}
	for _, a := range in.analyses { // ascending ID: later wins
		latest[[2]string{string(a.Ecosystem), a.Name}] = a
	}
	var out []model.LibraryAnalysis
	for _, a := range latest {
		if (f.Ecosystem == "" || a.Ecosystem == f.Ecosystem) && (f.Name == "" || a.Name == f.Name) &&
			(f.Verdict == "" || a.Verdict == f.Verdict) {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		return out[i].Name < out[j].Name
	})
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

func (s *Store) AnalysisHistory(_ context.Context, eco model.Ecosystem, name string, limit int) ([]model.LibraryAnalysis, error) {
	in := &s.intel
	in.mu.Lock()
	defer in.mu.Unlock()
	var out []model.LibraryAnalysis
	for i := len(in.analyses) - 1; i >= 0; i-- {
		if a := in.analyses[i]; a.Ecosystem == eco && a.Name == name {
			out = append(out, a)
			if limit > 0 && len(out) == limit {
				break
			}
		}
	}
	return out, nil
}
