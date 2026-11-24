package token

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/auth"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/secret"
)

// fakeStore resolves ID refs from a map and env/file refs like secret.EnvFile.
type fakeStore struct {
	ids   map[string]string
	calls int
}

func (f *fakeStore) Resolve(ctx context.Context, ref secret.Ref) (string, error) {
	f.calls++
	if ref.ID != "" {
		v, ok := f.ids[ref.ID]
		if !ok {
			return "", secret.ErrMissing
		}
		return v, nil
	}
	return secret.EnvFile{}.Resolve(ctx, ref)
}

func build(t *testing.T, cfg plugin.Config, res secret.Resolver) auth.TokenSource {
	t.Helper()
	c, err := New(cfg, plugin.Deps{Secrets: res})
	if err != nil {
		t.Fatal(err)
	}
	if c.Method() != "token" {
		t.Fatalf("Method = %q", c.Method())
	}
	return c.(auth.TokenSource)
}

func TestRegistered(t *testing.T) {
	if _, err := auth.Registry.Get("token"); err != nil {
		t.Fatal(err)
	}
}

func TestResolve(t *testing.T) {
	t.Setenv("HEIMDALL_TEST_TOKEN", "from-env")
	file := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(file, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{ids: map[string]string{"sec_1": "from-store"}}
	for name, tc := range map[string]struct {
		cfg  plugin.Config
		want string
	}{
		"env":  {plugin.Config{"token_env": "HEIMDALL_TEST_TOKEN"}, "from-env"},
		"file": {plugin.Config{"token_file": file}, "from-file"},
		"ref":  {plugin.Config{"token_ref": "sec_1"}, "from-store"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := build(t, tc.cfg, store).Token(context.Background(), "acme")
			if err != nil || got != tc.want {
				t.Fatalf("Token = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestCachesAndRefreshes(t *testing.T) {
	store := &fakeStore{ids: map[string]string{"s": "v1"}}
	src := build(t, plugin.Config{"token_ref": "s"}, store).(*Source)
	now := time.Unix(1000, 0)
	src.now = func() time.Time { return now }
	for range 3 {
		if v, _ := src.Token(context.Background(), ""); v != "v1" {
			t.Fatalf("Token = %q", v)
		}
	}
	if store.calls != 1 {
		t.Fatalf("resolver calls = %d, want 1", store.calls)
	}
	store.ids["s"] = "v2"
	now = now.Add(cacheTTL + time.Second)
	if v, _ := src.Token(context.Background(), ""); v != "v2" {
		t.Fatalf("after TTL Token = %q, want v2", v)
	}
}

func TestErrors(t *testing.T) {
	if _, err := New(plugin.Config{}, plugin.Deps{}); err == nil {
		t.Fatal("empty config must fail")
	}
	if _, err := New(plugin.Config{"token": "inline"}, plugin.Deps{}); err == nil {
		t.Fatal("unknown key must fail")
	}
	src := build(t, plugin.Config{"token_ref": "nope"}, &fakeStore{})
	if _, err := src.Token(context.Background(), ""); !errors.Is(err, secret.ErrMissing) {
		t.Fatalf("missing ref err = %v", err)
	}
	// nil resolver falls back to env/file
	t.Setenv("HEIMDALL_TEST_TOKEN2", "x")
	if v, err := build(t, plugin.Config{"token_env": "HEIMDALL_TEST_TOKEN2"}, nil).Token(context.Background(), ""); v != "x" || err != nil {
		t.Fatalf("Token = %q, %v", v, err)
	}
}
