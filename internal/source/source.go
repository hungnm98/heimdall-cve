// Package source is the port for check sources: vulnerability databases,
// enrichers, runtime EOL data and latest-version lookups.
//
// Every source must degrade gracefully: return an error and let the core mark
// it unhealthy for the run; never panic, never block other sources.
package source

import (
	"context"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/registry"
)

// VulnSource returns advisories affecting packages. Query is batched: the core
// passes every package of a run at once and the source splits as needed.
// Returned advisories must list, in Affected, the queried package they match.
// Private packages are never passed in.
type VulnSource interface {
	Name() string
	Supports(eco model.Ecosystem) bool
	Query(ctx context.Context, pkgs []model.Package) ([]model.Advisory, error)
}

// Enricher adds data (CVSS, EPSS, KEV...) to findings in place.
type Enricher interface {
	Name() string
	Enrich(ctx context.Context, findings []*model.Finding) error
}

// RuntimeSource evaluates runtime support status (EOL).
type RuntimeSource interface {
	Name() string
	Supports(runtime string) bool
	Evaluate(ctx context.Context, rt model.Runtime) (*model.RuntimeStatus, error)
}

// LatestVersionSource returns the latest published version of a package.
type LatestVersionSource interface {
	Name() string
	Supports(eco model.Ecosystem) bool
	Latest(ctx context.Context, p model.Package) (string, error)
}

// HealthChecker is optional: a cheap probe used by `sources list` and MCP list_sources.
type HealthChecker interface {
	Health(ctx context.Context) error
}

// Factories, one per kind.
type (
	VulnFactory     = func(cfg plugin.Config, deps plugin.Deps) (VulnSource, error)
	EnricherFactory = func(cfg plugin.Config, deps plugin.Deps) (Enricher, error)
	RuntimeFactory  = func(cfg plugin.Config, deps plugin.Deps) (RuntimeSource, error)
	LatestFactory   = func(cfg plugin.Config, deps plugin.Deps) (LatestVersionSource, error)
)

// Registries. A source name is unique within its kind; config `sources.<name>`
// is looked up in every registry, so one plugin may register in several kinds.
var (
	Vuln      = registry.New[VulnFactory]("vuln-source")
	Enrichers = registry.New[EnricherFactory]("enricher")
	Runtime   = registry.New[RuntimeFactory]("runtime-source")
	Latest    = registry.New[LatestFactory]("latest-version-source")
)

// CVEs returns the CVE ids among a finding's advisory id and aliases, in order.
func CVEs(f *model.Finding) []string {
	var out []string
	for _, id := range append([]string{f.AdvisoryID}, f.Aliases...) {
		if len(id) > 4 && id[:4] == "CVE-" {
			out = append(out, id)
		}
	}
	return out
}
