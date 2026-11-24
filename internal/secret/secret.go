// Package secret resolves secret references. Secrets are only ever read from
// environment variables or files named in config, never inlined in config or
// passed as CLI arguments.
package secret

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrMissing means neither the env var nor the file yielded a value.
var ErrMissing = errors.New("secret not set")

// Resolve returns the value of env var envName if set, otherwise the trimmed
// content of file. Both may be empty; at least one must yield a value.
func Resolve(envName, file string) (string, error) {
	if envName != "" {
		if v := strings.TrimSpace(os.Getenv(envName)); v != "" {
			return v, nil
		}
	}
	if file != "" {
		b, err := os.ReadFile(ExpandHome(file))
		if err != nil {
			return "", fmt.Errorf("read secret file: %w", err)
		}
		if v := strings.TrimSpace(string(b)); v != "" {
			return v, nil
		}
	}
	return "", fmt.Errorf("%w (env %q, file %q)", ErrMissing, envName, file)
}

// ExpandHome replaces a leading "~/" with the user's home directory.
func ExpandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

// Redact hides all but the last 4 characters, for logs and `config show`.
func Redact(v string) string {
	if len(v) <= 4 {
		return "****"
	}
	return "****" + v[len(v)-4:]
}
