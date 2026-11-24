// Package ssh is the "ssh" auth method: git over SSH with a key file, a key
// held in the secret store, or the ssh-agent.
package ssh

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hungnm98/heimdall-cve/internal/auth"
	"github.com/hungnm98/heimdall-cve/internal/gitx"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/secret"
)

func init() { auth.Registry.Register("ssh", New) }

// Config is the profile block. With neither key_file nor key_ref set, ssh
// uses the agent / default keys.
type Config struct {
	KeyFile    string `mapstructure:"key_file"`
	KeyRef     string `mapstructure:"key_ref"` // id in the encrypted secret store
	KnownHosts string `mapstructure:"known_hosts"`
}

// Validate implements plugin.Validator.
func (c *Config) Validate() error {
	if c.KeyFile != "" && c.KeyRef != "" {
		return fmt.Errorf("set key_file or key_ref, not both")
	}
	return nil
}

// Source is an SSHSource. Close removes a key materialised from key_ref.
type Source struct {
	ssh gitx.SSH

	mu      sync.Mutex
	tempKey string
}

// New builds an SSH source. A key_ref is resolved immediately (SSH() cannot
// fail or take a context) and written to a 0600 file under deps.CacheDir.
func New(raw plugin.Config, deps plugin.Deps) (auth.Credentials, error) {
	var cfg Config
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("ssh: %w", err)
	}
	s := &Source{ssh: gitx.SSH{
		KeyFile:        secret.ExpandHome(cfg.KeyFile),
		KnownHostsFile: secret.ExpandHome(cfg.KnownHosts),
	}}
	if cfg.KeyRef == "" {
		return s, nil
	}
	res := deps.Secrets
	if res == nil {
		res = secret.EnvFile{}
	}
	key, err := res.Resolve(context.Background(), secret.Ref{ID: cfg.KeyRef})
	if err != nil {
		return nil, fmt.Errorf("ssh: resolve key_ref: %w", err)
	}
	path, err := writeKey(deps.CacheDir, key)
	if err != nil {
		return nil, fmt.Errorf("ssh: %w", err)
	}
	s.ssh.KeyFile, s.tempKey = path, path
	return s, nil
}

func writeKey(cacheDir, key string) (string, error) {
	if cacheDir == "" {
		cacheDir = os.TempDir()
	}
	dir := filepath.Join(cacheDir, "ssh-keys")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create key dir: %w", err)
	}
	f, err := os.CreateTemp(dir, "key-*")
	if err != nil {
		return "", fmt.Errorf("create key file: %w", err)
	}
	path := f.Name()
	// OpenSSH rejects a private key without a trailing newline; the
	// resolver trims it.
	_, werr := f.WriteString(strings.TrimSpace(key) + "\n")
	cerr := f.Close()
	if err := os.Chmod(path, 0o600); err != nil && werr == nil {
		werr = err
	}
	if werr != nil || cerr != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("write key file: %v %v", werr, cerr)
	}
	return path, nil
}

// Method implements auth.Credentials.
func (*Source) Method() string { return "ssh" }

// SSH implements auth.SSHSource.
func (s *Source) SSH() gitx.SSH { return s.ssh }

// Close removes the temporary key file, if any.
func (s *Source) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tempKey == "" {
		return nil
	}
	err := os.Remove(s.tempKey)
	s.tempKey = ""
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

var _ auth.SSHSource = (*Source)(nil)
