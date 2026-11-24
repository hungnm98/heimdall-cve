package secret

import (
	"context"
	"errors"
)

// ErrUnsupported is returned by a Resolver that cannot handle a kind of Ref.
var ErrUnsupported = errors.New("secret reference not supported by this resolver")

// Ref says where a secret lives. Exactly one field is normally set; when
// several are, ID wins, then Env, then File.
type Ref struct {
	Env  string // environment variable name
	File string // file path
	ID   string // id in the encrypted secret store (secrets entered in the web UI)
}

// IsZero reports whether no location is set.
func (r Ref) IsZero() bool { return r.Env == "" && r.File == "" && r.ID == "" }

// Resolver turns a Ref into the secret value. Plugins get one through
// plugin.Deps and must use it for every secret, so new backends (encrypted
// store, Vault, cloud secret managers) need no plugin change.
type Resolver interface {
	Resolve(ctx context.Context, ref Ref) (string, error)
}

// EnvFile resolves Env and File refs. It is the default Resolver.
type EnvFile struct{}

// Resolve implements Resolver.
func (EnvFile) Resolve(_ context.Context, ref Ref) (string, error) {
	if ref.ID != "" {
		return "", ErrUnsupported
	}
	return Resolve(ref.Env, ref.File)
}

// Chain tries the encrypted store for ID refs and falls back to env/file.
type Chain struct {
	Store Resolver // handles ID refs; may be nil when no master key is configured
}

// Resolve implements Resolver.
func (c Chain) Resolve(ctx context.Context, ref Ref) (string, error) {
	if ref.ID != "" {
		if c.Store == nil {
			return "", errors.New("secret store disabled: no master key configured")
		}
		return c.Store.Resolve(ctx, ref)
	}
	return EnvFile{}.Resolve(ctx, ref)
}
