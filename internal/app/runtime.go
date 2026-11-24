package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/config"
	"github.com/hungnm98/heimdall-cve/internal/core"
	"github.com/hungnm98/heimdall-cve/internal/jobs"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/secret"
	"github.com/hungnm98/heimdall-cve/internal/service"
	"github.com/hungnm98/heimdall-cve/internal/store"
	"github.com/hungnm98/heimdall-cve/internal/vcs"
)

// Pipeline builds the scan pipeline from the configured plugins.
// providerFor resolves a target's VCS provider (config or catalog credentials).
func (a *App) Pipeline(cat store.Catalog, providerFor func(context.Context, model.Target) (vcs.Provider, error)) *core.Pipeline {
	cfg := a.Config
	return &core.Pipeline{
		Store: a.Store, Catalog: cat, ProviderFor: providerFor,
		Ecosystems: a.Ecosystems, Detectors: a.Detectors,
		VulnSources: a.VulnSources, RuntimeSources: a.RuntimeSources, Enrichers: a.Enrichers,
		Notifiers: a.Notifiers, Reporters: a.Reporters,
		Policy: cfg.Policy, SkipPaths: cfg.SkipPaths, Concurrency: cfg.Concurrency.Repos,
		ReportDir: cfg.Report.Dir, UIBaseURL: strings.TrimSuffix(cfg.Server.PublicURL, "/"),
		SnapshotSalt: snapshotSalt(cfg),
		Logger:       a.Logger, Now: time.Now,
	}
}

// snapshotSalt captures the config that shapes parse results (private
// modules), so changing it invalidates commit snapshots.
func snapshotSalt(cfg *config.Config) string {
	return "private=" + strings.Join(cfg.PrivateModules, ",")
}

// ConfigProviderFor resolves providers for config targets only (CLI scans).
func (a *App) ConfigProviderFor(_ context.Context, t model.Target) (vcs.Provider, error) {
	return a.Provider(t)
}

// WebRuntime is what `serve` and `worker` share.
type WebRuntime struct {
	Deps    service.Deps
	Jobs    jobs.Backend
	Scanner *core.Pipeline
}

// NewWebRuntime wires the catalog, the encrypted secret store, the jobs
// backend and the scan pipeline, then mirrors config targets and auth
// profiles into the catalog. Close the returned Jobs backend when done.
func (a *App) NewWebRuntime(ctx context.Context) (*WebRuntime, error) {
	cfg := a.Config
	cat, ok := a.Store.(store.Catalog)
	if !ok {
		return nil, fmt.Errorf("store %q does not implement the catalog (targets, jobs, audit) the web app needs", cfg.Store.Type)
	}
	keys, err := a.MasterKeys()
	if err != nil {
		return nil, fmt.Errorf("master key: %w", err)
	}
	if keys == nil {
		a.Logger.Warn("no master key configured: secrets cannot be entered in the UI", "env", cfg.Secrets.MasterKeyEnv)
	} else {
		// Plugins built from now on (catalog auth profiles) resolve *_ref
		// secrets from the encrypted store.
		a.Deps.Secrets = secret.Chain{Store: service.NewSecretResolver(cat, keys)}
	}
	backend, err := a.NewJobs()
	if err != nil {
		return nil, err
	}
	providerFor := a.CatalogProviderFor(cat)
	scanner := a.Pipeline(cat, providerFor)
	deps := service.Deps{
		Config: cfg, Store: a.Store, Catalog: cat, Jobs: backend, Scanner: scanner,
		Keys: keys, Secrets: a.Deps.Secrets, ProviderFor: providerFor,
		Notifiers: a.Notifiers, SourceKinds: a.SourceKinds(),
		Logger: a.Logger, Now: time.Now,
	}
	if err := service.SyncConfig(ctx, deps); err != nil {
		a.Logger.Warn("config sync incomplete", "err", err)
	}
	return &WebRuntime{Deps: deps, Jobs: backend, Scanner: scanner}, nil
}
