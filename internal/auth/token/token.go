// Package token is the "token" auth method: a static bearer token (classic or
// fine-grained PAT, GITHUB_TOKEN...) read from an env var, a file or the
// encrypted secret store.
package token

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/auth"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/secret"
)

func init() { auth.Registry.Register("token", New) }

// Config is the profile block. Exactly one location is normally set.
type Config struct {
	TokenEnv  string `mapstructure:"token_env"`
	TokenFile string `mapstructure:"token_file"`
	TokenRef  string `mapstructure:"token_ref"` // id in the encrypted secret store
}

// Validate implements plugin.Validator.
func (c *Config) Validate() error {
	if c.TokenEnv == "" && c.TokenFile == "" && c.TokenRef == "" {
		return errors.New("one of token_env, token_file or token_ref is required")
	}
	return nil
}

// cacheTTL bounds how long a resolved token is reused, so a rotated secret is
// picked up without a restart while the store is not hit on every API call.
const cacheTTL = 5 * time.Minute

// Source is a TokenSource backed by a secret reference.
type Source struct {
	ref     secret.Ref
	secrets secret.Resolver
	now     func() time.Time

	mu      sync.Mutex
	value   string
	expires time.Time
}

// New builds a token source. The secret is resolved lazily on first use: the
// encrypted store may only be wired in after plugins are built.
func New(raw plugin.Config, deps plugin.Deps) (auth.Credentials, error) {
	var cfg Config
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}
	res := deps.Secrets
	if res == nil {
		res = secret.EnvFile{}
	}
	return &Source{
		ref:     secret.Ref{Env: cfg.TokenEnv, File: cfg.TokenFile, ID: cfg.TokenRef},
		secrets: res,
		now:     time.Now,
	}, nil
}

// Method implements auth.Credentials.
func (*Source) Method() string { return "token" }

// Token implements auth.TokenSource. owner is ignored.
func (s *Source) Token(ctx context.Context, _ string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.value != "" && s.now().Before(s.expires) {
		return s.value, nil
	}
	v, err := s.secrets.Resolve(ctx, s.ref)
	if err != nil {
		return "", fmt.Errorf("token: resolve secret: %w", err)
	}
	if v == "" {
		return "", fmt.Errorf("token: %w", secret.ErrMissing)
	}
	s.value, s.expires = v, s.now().Add(cacheTTL)
	return v, nil
}

var _ auth.TokenSource = (*Source)(nil)
