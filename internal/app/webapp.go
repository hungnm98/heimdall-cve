package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/hungnm98/heimdall-cve/internal/auth"
	"github.com/hungnm98/heimdall-cve/internal/jobs"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/secret"
	"github.com/hungnm98/heimdall-cve/internal/source"
	"github.com/hungnm98/heimdall-cve/internal/store"
	"github.com/hungnm98/heimdall-cve/internal/vcs"
)

// Helpers for `heimdall serve` (and later `worker`).

// NewJobs builds the configured jobs backend (`jobs.type`, default inline).
func (a *App) NewJobs() (jobs.Backend, error) {
	typ := a.Config.Jobs.Type
	if typ == "" {
		typ = "inline"
	}
	b, err := build(jobs.Registry, typ, a.Config.Jobs.Options, a.Deps)
	if err != nil {
		return nil, fmt.Errorf("jobs: %w", err)
	}
	return b, nil
}

// MasterKeys loads the master key ring from secrets.master_key_env /
// master_key_file. Several comma-separated keys are allowed: the first seals,
// the others only open (KEK rotation). It returns nil, nil when no key is set.
func (a *App) MasterKeys() (*secret.KeyRing, error) {
	sc := a.Config.Secrets
	if sc.MasterKeyEnv == "" && sc.MasterKeyFile == "" {
		return nil, nil
	}
	v, err := secret.Resolve(sc.MasterKeyEnv, sc.MasterKeyFile)
	if errors.Is(err, secret.ErrMissing) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return secret.NewKeyRing(strings.Split(v, ",")...)
}

// SourceKinds maps each enabled source to the registries its type is in.
func (a *App) SourceKinds() map[string][]string {
	regs := []struct {
		kind string
		has  func(string) bool
	}{
		{source.Vuln.Kind(), func(t string) bool { _, err := source.Vuln.Get(t); return err == nil }},
		{source.Enrichers.Kind(), func(t string) bool { _, err := source.Enrichers.Get(t); return err == nil }},
		{source.Runtime.Kind(), func(t string) bool { _, err := source.Runtime.Get(t); return err == nil }},
		{source.Latest.Kind(), func(t string) bool { _, err := source.Latest.Get(t); return err == nil }},
	}
	out := map[string][]string{}
	for name, p := range a.Config.Sources {
		if !p.IsEnabled() {
			continue
		}
		kinds := []string{}
		for _, r := range regs {
			if r.has(p.TypeOr(name)) {
				kinds = append(kinds, r.kind)
			}
		}
		out[name] = kinds
	}
	return out
}

// CatalogProviderFor returns a function that builds a VCS provider for a
// target, with credentials built from the catalog's auth profiles (UI and
// config ones alike). Secrets referenced by "<kind>_ref" options resolve
// through a.Deps.Secrets.
func (a *App) CatalogProviderFor(cat store.Catalog) func(ctx context.Context, t model.Target) (vcs.Provider, error) {
	var mu sync.Mutex
	cache := map[string]vcs.Provider{}
	profile := func(ctx context.Context, name string) (*model.AuthProfile, error) {
		p, err := cat.GetAuthProfile(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("auth profile %q: %w", name, err)
		}
		return p, nil
	}
	creds := func(p *model.AuthProfile) (auth.Credentials, error) {
		c, err := build(auth.Registry, p.Type, plugin.Config(p.Options), a.Deps)
		if err != nil {
			return nil, fmt.Errorf("auth profile %q: %w", p.Name, err)
		}
		return c, nil
	}
	return func(ctx context.Context, t model.Target) (vcs.Provider, error) {
		provider := t.Provider
		if provider == "" {
			provider = "github"
		}
		listName := t.ListAuth
		if listName == "" {
			listName = t.Auth
		}
		read, err := profile(ctx, t.Auth)
		if err != nil {
			return nil, err
		}
		list, err := profile(ctx, listName)
		if err != nil {
			return nil, err
		}
		// Reuse a provider (and the tokens its credentials cache) until a
		// profile changes; UpdatedAt moves on every edit or secret change.
		key := fmt.Sprintf("%s|%s|%s@%d|%s@%d", provider, t.BaseURL, read.Name, read.UpdatedAt.UnixNano(), list.Name, list.UpdatedAt.UnixNano())
		mu.Lock()
		defer mu.Unlock()
		if p, ok := cache[key]; ok {
			return p, nil
		}
		f, err := vcs.Registry.Get(provider)
		if err != nil {
			return nil, err
		}
		rc, err := creds(read)
		if err != nil {
			return nil, err
		}
		lc := rc
		if list.Name != read.Name {
			if lc, err = creds(list); err != nil {
				return nil, err
			}
		}
		opts := plugin.Config{}
		if t.BaseURL != "" {
			opts["base_url"] = t.BaseURL
		}
		p, err := f(opts, vcs.Credentials{Read: rc, List: lc}, a.Deps)
		if err != nil {
			return nil, err
		}
		cache[key] = p
		return p, nil
	}
}
