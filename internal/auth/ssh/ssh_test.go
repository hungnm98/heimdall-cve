package ssh

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/auth"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/secret"
)

type fakeStore map[string]string

func (f fakeStore) Resolve(_ context.Context, ref secret.Ref) (string, error) {
	if v, ok := f[ref.ID]; ok {
		return v, nil
	}
	return "", secret.ErrMissing
}

func TestRegistered(t *testing.T) {
	if _, err := auth.Registry.Get("ssh"); err != nil {
		t.Fatal(err)
	}
}

func TestKeyFileAndAgent(t *testing.T) {
	c, err := New(plugin.Config{"key_file": "/k/id", "known_hosts": "/k/kh"}, plugin.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	s := c.(auth.SSHSource)
	if s.Method() != "ssh" || s.SSH().KeyFile != "/k/id" || s.SSH().KnownHostsFile != "/k/kh" {
		t.Fatalf("got %q %+v", s.Method(), s.SSH())
	}
	c, err = New(plugin.Config{}, plugin.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.(auth.SSHSource).SSH(); got.KeyFile != "" {
		t.Fatalf("agent mode KeyFile = %q", got.KeyFile)
	}
}

func TestKeyRef(t *testing.T) {
	cache := t.TempDir()
	c, err := New(plugin.Config{"key_ref": "k1"}, plugin.Deps{CacheDir: cache, Secrets: fakeStore{"k1": "PRIVATE KEY"}})
	if err != nil {
		t.Fatal(err)
	}
	s := c.(*Source)
	path := s.SSH().KeyFile
	if !strings.HasPrefix(path, filepath.Join(cache, "ssh-keys")) {
		t.Fatalf("key file %q not under cache dir", path)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", st.Mode().Perm())
	}
	if b, _ := os.ReadFile(path); string(b) != "PRIVATE KEY\n" {
		t.Fatalf("content = %q", b)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("key file not removed: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestErrors(t *testing.T) {
	if _, err := New(plugin.Config{"key_ref": "missing"}, plugin.Deps{CacheDir: t.TempDir(), Secrets: fakeStore{}}); err == nil {
		t.Fatal("missing key_ref must fail")
	}
	if _, err := New(plugin.Config{"key_ref": "a", "key_file": "b"}, plugin.Deps{}); err == nil {
		t.Fatal("key_ref + key_file must fail")
	}
	if _, err := New(plugin.Config{"key": "inline"}, plugin.Deps{}); err == nil {
		t.Fatal("unknown key must fail")
	}
}
