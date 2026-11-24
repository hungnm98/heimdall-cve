package app

import (
	"context"
	"errors"
	"fmt"
	"strings"

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
	creds := func(ctx context.Context, name string) (auth.Credentials, error) {
		p, err := cat.GetAuthProfile(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("auth profile %q: %w", name, err)
		}
		c, err := build(auth.Registry, p.Type, plugin.Config(p.Options), a.Deps)
		if err != nil {
			return nil, fmt.Errorf("auth profile %q: %w", name, err)
		}
		return c, nil
	}
	return func(ctx context.Context, t model.Target) (vcs.Provider, error) {
		provider := t.Provider
		if provider == "" {
			provider = "github"
		}
		f, err := vcs.Registry.Get(provider)
		if err != nil {
			return nil, err
		}
		read, err := creds(ctx, t.Auth)
		if err != nil {
			return nil, err
		}
		list := read
		if t.ListAuth != "" && t.ListAuth != t.Auth {
			if list, err = creds(ctx, t.ListAuth); err != nil {
				return nil, err
			}
		}
		opts := plugin.Config{}
		if t.BaseURL != "" {
			opts["base_url"] = t.BaseURL
		}
		return f(opts, vcs.Credentials{Read: read, List: list}, a.Deps)
	}
}
