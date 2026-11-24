// Package plugin holds what every plugin factory receives: its own raw config
// block and the shared dependencies.
package plugin

import (
	"fmt"
	"log/slog"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hungnm98/heimdall-cve/internal/gitx"
	"github.com/hungnm98/heimdall-cve/internal/httpx"
	"github.com/hungnm98/heimdall-cve/internal/secret"
)

// Config is a plugin's raw config block. Core never interprets it; the plugin
// decodes it into its own struct.
type Config map[string]any

// Validator is implemented by plugin config structs that need checks beyond types.
type Validator interface {
	Validate() error
}

// Decode decodes c into out (a pointer to the plugin's config struct, using
// `mapstructure` tags). Unknown keys are an error so typos fail fast. If out
// implements Validator, Validate is called.
func (c Config) Decode(out any) error {
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:           out,
		ErrorUnused:      true,
		WeaklyTypedInput: true,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
		),
	})
	if err != nil {
		return err
	}
	if err := dec.Decode(map[string]any(c)); err != nil {
		return fmt.Errorf("decode config: %w", err)
	}
	if v, ok := out.(Validator); ok {
		if err := v.Validate(); err != nil {
			return fmt.Errorf("invalid config: %w", err)
		}
	}
	return nil
}

// Deps are the shared services injected into every plugin factory.
type Deps struct {
	Logger   *slog.Logger
	HTTP     *httpx.Client
	Cache    *httpx.Cache // may be nil (caching disabled)
	Git      gitx.Runner
	CacheDir string // for plugins that keep their own files (offline DBs...)
	// WorkspaceDir caches repo content between scans (git mirrors, manifests by
	// commit SHA) so unchanged repos are never cloned or downloaded again.
	WorkspaceDir string
	// Secrets resolves every secret reference (env, file, encrypted store id).
	Secrets secret.Resolver
}
