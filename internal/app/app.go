// Package app is the composition root: it turns a validated config into live
// plugin instances. It is the only internal package (besides cmd) allowed to
// import adapters, and it does so only through plugins.go.
package app

import (
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"

	"github.com/hungnm98/heimdall-cve/internal/auth"
	"github.com/hungnm98/heimdall-cve/internal/config"
	"github.com/hungnm98/heimdall-cve/internal/ecosystem"
	"github.com/hungnm98/heimdall-cve/internal/gitx"
	"github.com/hungnm98/heimdall-cve/internal/httpx"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/notify"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/registry"
	"github.com/hungnm98/heimdall-cve/internal/report"
	"github.com/hungnm98/heimdall-cve/internal/runtime"
	"github.com/hungnm98/heimdall-cve/internal/secret"
	"github.com/hungnm98/heimdall-cve/internal/source"
	"github.com/hungnm98/heimdall-cve/internal/store"
	"github.com/hungnm98/heimdall-cve/internal/vcs"
)

// runtimeOf maps an ecosystem to the runtime its detectors look for.
var runtimeOf = map[string]string{"go": "go", "npm": "node", "rubygems": "ruby"}

// App holds every plugin instance built from config.
type App struct {
	Config  *config.Config
	Logger  *slog.Logger
	Deps    plugin.Deps
	Targets []model.Target
	Store   store.Store

	Credentials    map[string]auth.Credentials // by auth profile name
	providers      map[string]vcs.Provider     // by providerKey
	Ecosystems     []ecosystem.Ecosystem
	Detectors      []runtime.Detector
	VulnSources    []source.VulnSource
	Enrichers      []source.Enricher
	RuntimeSources []source.RuntimeSource
	LatestSources  []source.LatestVersionSource
	Notifiers      []notify.Notifier
	Reporters      []report.Reporter
}

// New builds every plugin. All errors are collected so a misconfigured
// deployment shows every problem at once.
func New(cfg *config.Config, logger *slog.Logger) (*App, error) {
	deps, err := newDeps(cfg, logger)
	if err != nil {
		return nil, err
	}
	a := &App{
		Config: cfg, Logger: logger, Deps: deps, Targets: cfg.ModelTargets(),
		Credentials: map[string]auth.Credentials{}, providers: map[string]vcs.Provider{},
	}
	var errs []error
	collect := func(what string, err error) {
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", what, err))
		}
	}

	a.Store, err = build(store.Registry, cfg.Store.Type, cfg.Store.Options, deps)
	collect("store", err)

	for name, p := range cfg.AuthProfiles {
		c, err := build(auth.Registry, p.Type, p.Options, deps)
		collect("auth_profiles."+name, err)
		a.Credentials[name] = c
	}
	for _, t := range a.Targets {
		key := providerKey(t)
		if _, done := a.providers[key]; done {
			continue
		}
		f, err := vcs.Registry.Get(t.Provider)
		if err != nil {
			collect("target "+t.String(), err)
			continue
		}
		read, list := a.Credentials[t.Auth], a.Credentials[t.ListAuth]
		if read == nil || list == nil {
			continue // auth error already collected
		}
		opts := plugin.Config{}
		if t.BaseURL != "" {
			opts["base_url"] = t.BaseURL
		}
		p, err := f(opts, vcs.Credentials{Read: read, List: list}, deps)
		collect("target "+t.String(), err)
		a.providers[key] = p
	}

	ecoOpts := ecosystem.Options{PrivatePatterns: cfg.PrivateModules}
	wantRuntime := map[string]bool{}
	ecoNames := cfg.Ecosystems
	if len(ecoNames) == 0 {
		// Default: scan every ecosystem compiled in, so a repo holding Go,
		// Node.js and Ruby projects is scanned for all three in one pass.
		ecoNames = ecosystem.Registry.Names()
	}
	for _, name := range ecoNames {
		f, err := ecosystem.Registry.Get(name)
		if err != nil {
			collect("ecosystems", err)
			continue
		}
		e, err := f(nil, ecoOpts, deps)
		collect("ecosystem "+name, err)
		if e != nil {
			a.Ecosystems = append(a.Ecosystems, e)
		}
		wantRuntime[runtimeOf[name]] = true
	}
	for _, name := range runtime.Registry.Names() {
		d, err := build(runtime.Registry, name, nil, deps)
		collect("runtime detector "+name, err)
		if d != nil && wantRuntime[d.Runtime()] {
			a.Detectors = append(a.Detectors, d)
		}
	}

	for _, name := range sortedNames(cfg.Sources) {
		p := cfg.Sources[name]
		if !p.IsEnabled() {
			continue
		}
		collect("sources."+name, a.addSource(p.TypeOr(name), p.Options, deps))
	}
	for _, name := range sortedNames(cfg.Notify) {
		p := cfg.Notify[name]
		if !p.IsEnabled() {
			continue
		}
		n, err := build(notify.Registry, p.TypeOr(name), p.Options, deps)
		collect("notify."+name, err)
		if n != nil {
			a.Notifiers = append(a.Notifiers, n)
		}
	}
	for _, format := range cfg.Report.Formats {
		r, err := build(report.Registry, format, nil, deps)
		collect("report format", err)
		if r != nil {
			a.Reporters = append(a.Reporters, r)
		}
	}
	if err := errors.Join(errs...); err != nil {
		_ = a.Close()
		return nil, err
	}
	return a, nil
}

func newDeps(cfg *config.Config, logger *slog.Logger) (plugin.Deps, error) {
	cache, err := httpx.NewCache(filepath.Join(cfg.Cache.Dir, "http"), cfg.Cache.TTL)
	if err != nil {
		return plugin.Deps{}, err
	}
	return plugin.Deps{
		Logger:       logger,
		HTTP:         httpx.New(httpx.Options{PerHost: cfg.Concurrency.HTTPPerHost, Logger: logger}),
		Cache:        cache,
		Git:          gitx.Runner{},
		CacheDir:     cfg.Cache.Dir,
		WorkspaceDir: cfg.Workspace.Dir,
		// The encrypted store resolver is plugged in by `serve`/`worker`
		// once the master key and DB are available.
		Secrets: secret.Chain{},
	}, nil
}

// OpenStore builds only the configured store, for commands such as
// `heimdall db migrate` that must work before other plugins are configured.
func OpenStore(cfg *config.Config, logger *slog.Logger) (store.Store, error) {
	deps, err := newDeps(cfg, logger)
	if err != nil {
		return nil, err
	}
	s, err := build(store.Registry, cfg.Store.Type, cfg.Store.Options, deps)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return s, nil
}

// addSource instantiates typ from every source registry it is registered in.
func (a *App) addSource(typ string, opts plugin.Config, deps plugin.Deps) error {
	found := false
	var errs []error
	if f, err := source.Vuln.Get(typ); err == nil {
		found = true
		s, err := f(opts, deps)
		errs = append(errs, err)
		if s != nil {
			a.VulnSources = append(a.VulnSources, s)
		}
	}
	if f, err := source.Enrichers.Get(typ); err == nil {
		found = true
		s, err := f(opts, deps)
		errs = append(errs, err)
		if s != nil {
			a.Enrichers = append(a.Enrichers, s)
		}
	}
	if f, err := source.Runtime.Get(typ); err == nil {
		found = true
		s, err := f(opts, deps)
		errs = append(errs, err)
		if s != nil {
			a.RuntimeSources = append(a.RuntimeSources, s)
		}
	}
	if f, err := source.Latest.Get(typ); err == nil {
		found = true
		s, err := f(opts, deps)
		errs = append(errs, err)
		if s != nil {
			a.LatestSources = append(a.LatestSources, s)
		}
	}
	if !found {
		return fmt.Errorf("source type %q: %w", typ, registry.ErrNotFound)
	}
	return errors.Join(errs...)
}

// Provider returns the VCS provider serving target t.
func (a *App) Provider(t model.Target) (vcs.Provider, error) {
	p, ok := a.providers[providerKey(t)]
	if !ok || p == nil {
		return nil, fmt.Errorf("no provider for %s", t)
	}
	return p, nil
}

// Close releases plugin resources.
func (a *App) Close() error {
	if a.Store != nil {
		return a.Store.Close()
	}
	return nil
}

func providerKey(t model.Target) string {
	return t.Provider + "|" + t.BaseURL + "|" + t.Auth + "|" + t.ListAuth
}

// build looks a factory up and calls it; F must be func(plugin.Config, plugin.Deps) (T, error).
func build[T any](r *registry.Registry[func(plugin.Config, plugin.Deps) (T, error)], name string, opts plugin.Config, deps plugin.Deps) (T, error) {
	f, err := r.Get(name)
	if err != nil {
		var zero T
		return zero, err
	}
	return f(opts, deps)
}

func sortedNames(m map[string]config.Plugin) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
