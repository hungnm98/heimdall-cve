// Package auth is the port for credential providers (auth profiles).
//
// A profile in config (`auth_profiles.<name>.type`) maps to a registered
// Factory. A Credentials value exposes what it can do through capability
// interfaces: TokenSource for HTTP APIs, SSHSource for git over SSH.
package auth

import (
	"context"

	"github.com/hungnm98/heimdall-cve/internal/gitx"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/registry"
)

// Credentials is a resolved auth profile.
type Credentials interface {
	// Method is the profile type: "token", "app", "ssh"...
	Method() string
}

// TokenSource yields bearer tokens for an API. owner lets GitHub App
// credentials pick the installation of that org/user; others ignore it.
// Implementations cache and refresh tokens themselves.
type TokenSource interface {
	Credentials
	Token(ctx context.Context, owner string) (string, error)
}

// SSHSource provides SSH settings for git.
type SSHSource interface {
	Credentials
	SSH() gitx.SSH
}

// Factory builds Credentials from a profile's config block.
type Factory = func(cfg plugin.Config, deps plugin.Deps) (Credentials, error)

// Registry holds auth methods by type name.
var Registry = registry.New[Factory]("auth")
