// Package githubapp is the "app" auth method: a GitHub App that signs a JWT
// (RS256) with its private key and exchanges it for installation tokens. The
// installation is discovered per owner unless installation_id is set.
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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/auth"
	"github.com/hungnm98/heimdall-cve/internal/httpx"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/secret"
)

func init() { auth.Registry.Register("app", New) }

// Config is the profile block.
type Config struct {
	AppID          string `mapstructure:"app_id"`
	AppIDEnv       string `mapstructure:"app_id_env"`
	PrivateKeyFile string `mapstructure:"private_key_file"`
	PrivateKeyEnv  string `mapstructure:"private_key_env"`
	PrivateKeyRef  string `mapstructure:"private_key_ref"` // id in the encrypted secret store
	InstallationID int64  `mapstructure:"installation_id"` // 0 = discover per owner
	BaseURL        string `mapstructure:"base_url"`        // API root; GHES: https://host/api/v3
}

// Validate implements plugin.Validator.
func (c *Config) Validate() error {
	if c.AppID == "" && c.AppIDEnv == "" {
		return errors.New("app_id or app_id_env is required")
	}
	if c.PrivateKeyFile == "" && c.PrivateKeyEnv == "" && c.PrivateKeyRef == "" {
		return errors.New("one of private_key_file, private_key_env or private_key_ref is required")
	}
	if _, err := url.Parse(c.BaseURL); err != nil {
		return fmt.Errorf("base_url: %w", err)
	}
	return nil
}

const (
	apiVersion = "2022-11-28"
	// refreshBefore renews an installation token this long before it expires.
	refreshBefore = 5 * time.Minute
	jwtLifetime   = 9 * time.Minute // GitHub caps it at 10
	clockSkew     = 60 * time.Second
)

// Source is a TokenSource yielding installation tokens. Safe for concurrent use.
type Source struct {
	cfg     Config
	base    string
	http    *httpx.Client
	secrets secret.Resolver
	now     func() time.Time

	keyMu sync.Mutex
	appID string
	key   *rsa.PrivateKey

	discMu        sync.Mutex
	installations map[string]int64 // lower-case owner → installation id

	tokMu  sync.Mutex
	tokens map[int64]*installToken
}

type installToken struct {
	mu      sync.Mutex // held while (re)fetching, so concurrent callers share one request
	value   string
	expires time.Time
}

// New builds an App token source. Secrets are resolved lazily on first use.
func New(raw plugin.Config, deps plugin.Deps) (auth.Credentials, error) {
	cfg := Config{BaseURL: "https://api.github.com"}
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("app: %w", err)
	}
	if deps.HTTP == nil {
		return nil, errors.New("app: deps.HTTP is required")
	}
	res := deps.Secrets
	if res == nil {
		res = secret.EnvFile{}
	}
	return &Source{
		cfg:           cfg,
		base:          strings.TrimRight(cfg.BaseURL, "/"),
		http:          deps.HTTP,
		secrets:       res,
		now:           time.Now,
		installations: map[string]int64{},
		tokens:        map[int64]*installToken{},
	}, nil
}

// Method implements auth.Credentials.
func (*Source) Method() string { return "app" }

// Token implements auth.TokenSource: an installation token for owner's
// installation, cached until refreshBefore its expiry.
func (s *Source) Token(ctx context.Context, owner string) (string, error) {
	id, err := s.installation(ctx, owner)
	if err != nil {
		return "", err
	}
	s.tokMu.Lock()
	t, ok := s.tokens[id]
	if !ok {
		t = &installToken{}
		s.tokens[id] = t
	}
	s.tokMu.Unlock()

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.value != "" && s.now().Add(refreshBefore).Before(t.expires) {
		return t.value, nil
	}
	jwt, err := s.JWT(ctx)
	if err != nil {
		return "", err
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	u := fmt.Sprintf("%s/app/installations/%d/access_tokens", s.base, id)
	if err := s.http.PostJSON(ctx, u, s.header(jwt), struct{}{}, &out); err != nil {
		return "", fmt.Errorf("app: create installation token: %w", err)
	}
	if out.Token == "" {
		return "", errors.New("app: create installation token: empty token in response")
	}
	if out.ExpiresAt.IsZero() {
		out.ExpiresAt = s.now().Add(time.Hour)
	}
	t.value, t.expires = out.Token, out.ExpiresAt
	return t.value, nil
}

// installation returns the installation id for owner, discovering and caching it.
func (s *Source) installation(ctx context.Context, owner string) (int64, error) {
	if s.cfg.InstallationID != 0 {
		return s.cfg.InstallationID, nil
	}
	if owner == "" {
		return 0, errors.New("app: owner is required to discover the installation (or set installation_id)")
	}
	key := strings.ToLower(owner)
	s.discMu.Lock()
	defer s.discMu.Unlock()
	if id, ok := s.installations[key]; ok {
		return id, nil
	}
	jwt, err := s.JWT(ctx)
	if err != nil {
		return 0, err
	}
	var out struct {
		ID int64 `json:"id"`
	}
	esc := url.PathEscape(owner)
	err = s.http.GetJSON(ctx, s.base+"/orgs/"+esc+"/installation", s.header(jwt), &out)
	if isNotFound(err) {
		err = s.http.GetJSON(ctx, s.base+"/users/"+esc+"/installation", s.header(jwt), &out)
	}
	if isNotFound(err) {
		return 0, fmt.Errorf("app: app is not installed on %q", owner)
	}
	if err != nil {
		return 0, fmt.Errorf("app: discover installation for %q: %w", owner, err)
	}
	if out.ID == 0 {
		return 0, fmt.Errorf("app: discover installation for %q: no id in response", owner)
	}
	s.installations[key] = out.ID
	return out.ID, nil
}

func isNotFound(err error) bool {
	var se *httpx.StatusError
	return errors.As(err, &se) && se.Code == http.StatusNotFound
}

func (s *Source) header(jwt string) http.Header {
	return http.Header{
		"Authorization":        {"Bearer " + jwt},
		"Accept":               {"application/vnd.github+json"},
		"X-Github-Api-Version": {apiVersion},
	}
}

// JWT returns a freshly signed app JWT (RS256).
func (s *Source) JWT(ctx context.Context) (string, error) {
	appID, key, err := s.loadKey(ctx)
	if err != nil {
		return "", err
	}
	return signJWT(appID, key, s.now())
}

func (s *Source) loadKey(ctx context.Context) (string, *rsa.PrivateKey, error) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	if s.key != nil {
		return s.appID, s.key, nil
	}
	appID := s.cfg.AppID
	if appID == "" {
		v, err := s.secrets.Resolve(ctx, secret.Ref{Env: s.cfg.AppIDEnv})
		if err != nil {
			return "", nil, fmt.Errorf("app: resolve app_id: %w", err)
		}
		appID = v
	}
	if _, err := strconv.ParseInt(appID, 10, 64); err != nil {
		return "", nil, errors.New("app: app_id must be numeric")
	}
	pemStr, err := s.secrets.Resolve(ctx, secret.Ref{ID: s.cfg.PrivateKeyRef, Env: s.cfg.PrivateKeyEnv, File: s.cfg.PrivateKeyFile})
	if err != nil {
		return "", nil, fmt.Errorf("app: resolve private key: %w", err)
	}
	key, err := parseKey([]byte(pemStr))
	if err != nil {
		return "", nil, fmt.Errorf("app: %w", err)
	}
	s.appID, s.key = appID, key
	return appID, key, nil
}

// parseKey accepts PKCS#1 ("RSA PRIVATE KEY", what GitHub issues) and PKCS#8 PEM.
func parseKey(b []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("private key is not PEM encoded")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("private key: not a PKCS#1 or PKCS#8 RSA key")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key: not an RSA key")
	}
	return rk, nil
}

func signJWT(appID string, key *rsa.PrivateKey, now time.Time) (string, error) {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, err := json.Marshal(map[string]any{
		"iat": now.Add(-clockSkew).Unix(),
		"exp": now.Add(jwtLifetime).Unix(),
		"iss": appID,
	})
	if err != nil {
		return "", err
	}
	signing := header + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("app: sign JWT: %w", err)
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

var _ auth.TokenSource = (*Source)(nil)
