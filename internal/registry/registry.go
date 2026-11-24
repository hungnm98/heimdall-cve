// Package registry is a small typed plugin registry.
//
// Each port declares its own registry (e.g. source.Vuln = registry.New[source.VulnFactory]("vuln-source"))
// and each adapter package registers itself in init(). Which adapters are
// compiled in is decided by blank imports in internal/app/plugins.go.
package registry

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// ErrNotFound is returned by Get for an unknown plugin name.
var ErrNotFound = errors.New("plugin not registered")

// Registry maps plugin names to factories of type F.
type Registry[F any] struct {
	kind string
	mu   sync.RWMutex
	m    map[string]F
}

var (
	catalogMu sync.Mutex
	catalog   = map[string]func() []string{}
)

// New creates a registry for one plugin kind and lists it in the global catalog.
func New[F any](kind string) *Registry[F] {
	r := &Registry[F]{kind: kind, m: map[string]F{}}
	catalogMu.Lock()
	defer catalogMu.Unlock()
	if _, dup := catalog[kind]; dup {
		panic(fmt.Sprintf("registry: kind %q declared twice", kind))
	}
	catalog[kind] = r.Names
	return r
}

// Kind returns the plugin kind, e.g. "vuln-source".
func (r *Registry[F]) Kind() string { return r.kind }

// Register adds a factory. It panics on empty or duplicate names: both are
// programming errors that must fail at start-up, not at scan time.
func (r *Registry[F]) Register(name string, f F) {
	if name == "" {
		panic(fmt.Sprintf("registry %s: empty plugin name", r.kind))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.m[name]; dup {
		panic(fmt.Sprintf("registry %s: plugin %q registered twice", r.kind, name))
	}
	r.m[name] = f
}

// Get returns the factory for name.
func (r *Registry[F]) Get(name string) (F, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	f, ok := r.m[name]
	if !ok {
		var zero F
		return zero, fmt.Errorf("%s %q: %w (compiled in: %v)", r.kind, name, ErrNotFound, r.namesLocked())
	}
	return f, nil
}

// Names lists registered plugin names, sorted.
func (r *Registry[F]) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.namesLocked()
}

func (r *Registry[F]) namesLocked() []string {
	out := make([]string, 0, len(r.m))
	for n := range r.m {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Catalog returns every declared kind with its registered plugin names.
func Catalog() map[string][]string {
	catalogMu.Lock()
	defer catalogMu.Unlock()
	out := make(map[string][]string, len(catalog))
	for k, names := range catalog {
		out[k] = names()
	}
	return out
}
