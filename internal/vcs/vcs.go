// Package vcs is the port for version-control providers (GitHub now; GitLab,
// Bitbucket, Gitea later). A provider resolves targets into repos and reads
// files at a commit.
package vcs

import (
	"context"
	"errors"

	"github.com/hungnm98/heimdall-cve/internal/auth"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/registry"
)

// ErrNotFound is returned for a missing repo, ref or file.
var ErrNotFound = errors.New("not found")

// ErrUnsupported is returned when a provider/credential combination cannot do
// an operation (e.g. listing an org with SSH-only credentials).
var ErrUnsupported = errors.New("unsupported")

// Provider is one VCS host reached with one set of credentials.
type Provider interface {
	Name() string
	// ListRepos resolves an org, user or single-repo target into repos,
	// applying t.Filter and setting Repo.Ref (t.Branch or the default branch).
	ListRepos(ctx context.Context, t model.Target) ([]model.Repo, error)
	// ResolveRef returns the commit SHA a branch points to.
	ResolveRef(ctx context.Context, r model.Repo, ref string) (sha string, err error)
	// ListFiles returns every file path (repo-relative, "/"-separated) at sha.
	ListFiles(ctx context.Context, r model.Repo, sha string) ([]string, error)
	// ReadFile returns a file's content at sha.
	ReadFile(ctx context.Context, r model.Repo, sha, path string) ([]byte, error)
	// Checkout materialises the tree at sha into dir (shallow), for code scanning.
	Checkout(ctx context.Context, r model.Repo, sha, dir string) error
}

// Credentials passed to a provider factory.
type Credentials struct {
	Read auth.Credentials // used to read code (token, app or ssh)
	List auth.Credentials // used to list repos; equals Read unless list_auth is set
}

// Factory builds a Provider. cfg holds provider options such as base_url.
type Factory func(cfg plugin.Config, creds Credentials, deps plugin.Deps) (Provider, error)

// Registry holds providers by name ("github").
var Registry = registry.New[Factory]("vcs")
