package githubapp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/auth"
	"github.com/hungnm98/heimdall-cve/internal/httpx"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/secret"
)

var testKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

func pemPKCS1() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(testKey)}))
}

// verifyJWT checks the RS256 signature with the public key and returns the claims.
func verifyJWT(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts", len(parts))
	}
	enc := base64.RawURLEncoding
	var hdr map[string]string
	hb, _ := enc.DecodeString(parts[0])
	if err := json.Unmarshal(hb, &hdr); err != nil || hdr["alg"] != "RS256" {
		t.Fatalf("header = %s (%v)", hb, err)
	}
	sig, err := enc.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&testKey.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("signature: %v", err)
	}
	cb, _ := enc.DecodeString(parts[1])
	var claims map[string]any
	if err := json.Unmarshal(cb, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

type fakeGitHub struct {
	t         *testing.T
	srv       *httptest.Server
	mu        sync.Mutex
	now       func() time.Time
	installs  map[string]int64 // "orgs/acme" or "users/bob" → id
	tokenHits atomic.Int64
	discHits  atomic.Int64
}

func newFake(t *testing.T, now func() time.Time) *fakeGitHub {
	f := &fakeGitHub{t: t, now: now, installs: map[string]int64{"orgs/acme": 11, "users/bob": 22}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	jwt := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := verifyJWT(f.t, jwt)
	if claims["iss"] != "42" {
		f.t.Errorf("iss = %v", claims["iss"])
	}
	if r.Header.Get("X-GitHub-Api-Version") != apiVersion {
		f.t.Errorf("missing API version header")
	}
	p := strings.ToLower(strings.TrimPrefix(r.URL.Path, "/")) // logins are case-insensitive
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(p, "/installation"):
		f.discHits.Add(1)
		id, ok := f.installs[strings.TrimSuffix(p, "/installation")]
		if !ok {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		fmt.Fprintf(w, `{"id":%d}`, id)
	case r.Method == http.MethodPost && strings.HasPrefix(p, "app/installations/"):
		n := f.tokenHits.Add(1)
		var id int64
		fmt.Sscanf(p, "app/installations/%d/access_tokens", &id)
		exp := f.now().Add(time.Hour).UTC().Format(time.RFC3339)
		fmt.Fprintf(w, `{"token":"ghs_%d_%d","expires_at":%q}`, id, n, exp)
	default:
		http.NotFound(w, r)
	}
}

func newSource(t *testing.T, base string, extra plugin.Config, now *time.Time) *Source {
	t.Helper()
	cfg := plugin.Config{"app_id": 42, "private_key_env": "HEIMDALL_TEST_APP_KEY", "base_url": base}
	for k, v := range extra {
		cfg[k] = v
	}
	c, err := New(cfg, plugin.Deps{HTTP: httpx.New(httpx.Options{MaxRetries: 1}), Secrets: secret.EnvFile{}})
	if err != nil {
		t.Fatal(err)
	}
	s := c.(*Source)
	s.now = func() time.Time { return *now }
	return s
}

func TestRegistered(t *testing.T) {
	if _, err := auth.Registry.Get("app"); err != nil {
		t.Fatal(err)
	}
}

func TestJWT(t *testing.T) {
	t.Setenv("HEIMDALL_TEST_APP_KEY", pemPKCS1())
	now := time.Unix(1_700_000_000, 0)
	s := newSource(t, "http://unused", nil, &now)
	jwt, err := s.JWT(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c := verifyJWT(t, jwt)
	if c["iss"] != "42" || int64(c["iat"].(float64)) != now.Unix()-60 || int64(c["exp"].(float64)) != now.Add(9*time.Minute).Unix() {
		t.Fatalf("claims = %v", c)
	}
}

func TestPKCS8KeyFromFile(t *testing.T) {
	der, err := x509.MarshalPKCS8PrivateKey(testKey)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "app.pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HEIMDALL_TEST_APP_ID", "42")
	c, err := New(plugin.Config{"app_id_env": "HEIMDALL_TEST_APP_ID", "private_key_file": file}, plugin.Deps{HTTP: httpx.New(httpx.Options{})})
	if err != nil {
		t.Fatal(err)
	}
	jwt, err := c.(*Source).JWT(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	verifyJWT(t, jwt)
}

func TestInstallationDiscoveryAndCaching(t *testing.T) {
	t.Setenv("HEIMDALL_TEST_APP_KEY", pemPKCS1())
	now := time.Unix(1_700_000_000, 0)
	f := newFake(t, func() time.Time { return now })
	s := newSource(t, f.srv.URL, nil, &now)
	ctx := context.Background()

	// org install, cached across concurrent callers
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if tok, err := s.Token(ctx, "Acme"); err != nil || tok != "ghs_11_1" {
				t.Errorf("Token(acme) = %q, %v", tok, err)
			}
		})
	}
	wg.Wait()
	if f.tokenHits.Load() != 1 || f.discHits.Load() != 1 {
		t.Fatalf("token hits = %d, discovery hits = %d; want 1, 1", f.tokenHits.Load(), f.discHits.Load())
	}

	// user install: /orgs 404 then /users
	if tok, err := s.Token(ctx, "bob"); err != nil || tok != "ghs_22_2" {
		t.Fatalf("Token(bob) = %q, %v", tok, err)
	}
	if f.discHits.Load() != 3 {
		t.Fatalf("discovery hits = %d, want 3", f.discHits.Load())
	}

	// still fresh 50 minutes later (expires at +60m, refresh window 5m)
	now = now.Add(50 * time.Minute)
	if tok, _ := s.Token(ctx, "acme"); tok != "ghs_11_1" {
		t.Fatalf("Token after 50m = %q, want cached", tok)
	}
	// inside the refresh window → new token
	now = now.Add(6 * time.Minute)
	if tok, _ := s.Token(ctx, "acme"); tok != "ghs_11_3" {
		t.Fatalf("Token after 56m = %q, want refreshed ghs_11_3", tok)
	}
	if f.discHits.Load() != 3 {
		t.Fatalf("installation must stay cached, discovery hits = %d", f.discHits.Load())
	}

	// not installed
	if _, err := s.Token(ctx, "nobody"); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("Token(nobody) err = %v", err)
	}
}

func TestFixedInstallation(t *testing.T) {
	t.Setenv("HEIMDALL_TEST_APP_KEY", pemPKCS1())
	now := time.Unix(1_700_000_000, 0)
	f := newFake(t, func() time.Time { return now })
	s := newSource(t, f.srv.URL, plugin.Config{"installation_id": 99}, &now)
	if tok, err := s.Token(context.Background(), ""); err != nil || tok != "ghs_99_1" {
		t.Fatalf("Token = %q, %v", tok, err)
	}
	if f.discHits.Load() != 0 {
		t.Fatal("installation_id set: no discovery expected")
	}
}

func TestConfigErrors(t *testing.T) {
	deps := plugin.Deps{HTTP: httpx.New(httpx.Options{})}
	for _, cfg := range []plugin.Config{
		{"private_key_file": "x"},
		{"app_id": 1},
		{"app_id": 1, "private_key_file": "x", "private_key": "inline"},
	} {
		if _, err := New(cfg, deps); err == nil {
			t.Errorf("New(%v) must fail", cfg)
		}
	}
	t.Setenv("HEIMDALL_TEST_APP_KEY", "not a pem")
	now := time.Now()
	s := newSource(t, "http://unused", nil, &now)
	if _, err := s.JWT(context.Background()); err == nil {
		t.Fatal("bad key must fail")
	}
}
