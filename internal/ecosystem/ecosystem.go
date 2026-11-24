// Package ecosystem is the port for dependency-manifest parsers.
package ecosystem

import (
	"context"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/registry"
	"github.com/hungnm98/heimdall-cve/internal/version"
)

// Ecosystem parses one ecosystem's manifests.
type Ecosystem interface {
	Name() model.Ecosystem
	// Match reports whether a repo path is a manifest/lockfile this ecosystem reads.
	Match(path string) bool
	// Parse receives every matched file of one repo (so workspaces and root
	// lockfiles can be resolved) and returns one graph per manifest.
	Parse(ctx context.Context, files model.FileSet) ([]*model.DependencyGraph, error)
	// Versions compares versions of this ecosystem.
	Versions() version.Comparator
}

// Options are shared settings every ecosystem factory receives.
type Options struct {
	// PrivatePatterns are globs (e.g. "github.com/acme/*") for packages that
	// must be marked Private and never sent to public sources.
	PrivatePatterns []string
}

// Factory builds an Ecosystem.
type Factory func(cfg plugin.Config, opts Options, deps plugin.Deps) (Ecosystem, error)

// Registry holds ecosystems by name ("go").
var Registry = registry.New[Factory]("ecosystem")
