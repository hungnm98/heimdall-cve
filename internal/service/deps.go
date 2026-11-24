package service

import (
	"context"
	"log/slog"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/config"
	"github.com/hungnm98/heimdall-cve/internal/core"
	"github.com/hungnm98/heimdall-cve/internal/jobs"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/notify"
	"github.com/hungnm98/heimdall-cve/internal/secret"
	"github.com/hungnm98/heimdall-cve/internal/store"
	"github.com/hungnm98/heimdall-cve/internal/vcs"
)

// Deps is everything the service implementations, the job handler and the
// scheduler need. internal/app builds it; tests fill it with memstore,
// the inline jobs backend and fakes.
type Deps struct {
	Config  *config.Config
	Store   store.Store
	Catalog store.Catalog
	Jobs    jobs.Backend
	Scanner core.Scanner

	// Keys seals secrets entered in the UI; nil = no master key (secrets disabled).
	Keys *secret.KeyRing
	// Secrets resolves env/file/ID references (secret.Chain with the catalog-backed store).
	Secrets secret.Resolver

	// ProviderFor builds a VCS provider for a target using catalog auth
	// profiles (used by Targets.Preview and AuthProfiles.Test).
	ProviderFor func(ctx context.Context, t model.Target) (vcs.Provider, error)

	Notifiers []notify.Notifier
	// SourceKinds maps each enabled source name to the registries it is in.
	SourceKinds map[string][]string

	Logger *slog.Logger
	Now    func() time.Time
}
