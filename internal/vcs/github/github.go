// Package github is the GitHub (and GitHub Enterprise Server) VCS provider.
//
// Listing always goes through the REST API with creds.List. Reading code has
// two modes chosen by creds.Read:
//   - token / app (auth.TokenSource): Git Trees + Contents API; manifests are
//     cached on disk by commit SHA under the workspace dir. A truncated tree
//     falls back to git mode over HTTPS.
//   - ssh (auth.SSHSource): a shallow, blob-less bare mirror per repo under
//     the workspace dir, fetched incrementally.
package github

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/hungnm98/heimdall-cve/internal/auth"
	"github.com/hungnm98/heimdall-cve/internal/gitx"
	"github.com/hungnm98/heimdall-cve/internal/httpx"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/vcs"
)

func init() { vcs.Registry.Register("github", New) }

// Name is the provider name.
const Name = "github"

const defaultBaseURL = "https://api.github.com"

// Config holds provider options.
type Config struct {
	BaseURL string `mapstructure:"base_url"` // API root; GHES: https://host/api/v3
}

// Validate implements plugin.Validator.
func (c *Config) Validate() error {
	u, err := url.Parse(c.BaseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("base_url %q: want http(s)://host[/path]", c.BaseURL)
	}
	return nil
}

// Provider implements vcs.Provider. Safe for concurrent use.
type Provider struct {
	api  string // API root without trailing slash
	host string // web host, e.g. github.com
	web  string // web root, e.g. https://github.com

	list      auth.Credentials
	readToken auth.TokenSource // API read mode
	readSSH   *gitx.SSH        // SSH read mode

	http *httpx.Client
	git  gitx.Runner
	ws   string
	log  *slog.Logger

	// sshBase overrides the SSH remote prefix (sshBase + "owner/name.git");
	// tests point it at a local file:// directory.
	sshBase string

	locks sync.Map // mirror dir → *sync.Mutex

	userMu    sync.Mutex
	userLogin *string // login of the List token, once looked up
}

// New is the vcs.Factory for GitHub.
func New(raw plugin.Config, creds vcs.Credentials, deps plugin.Deps) (vcs.Provider, error) {
	cfg := Config{BaseURL: defaultBaseURL}
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("github: %w", err)
	}
	if deps.HTTP == nil {
		return nil, errors.New("github: deps.HTTP is required")
	}
	if creds.Read == nil {
		return nil, errors.New("github: read credentials are required")
	}
	p := &Provider{
		api:  strings.TrimRight(cfg.BaseURL, "/"),
		list: creds.List,
		http: deps.HTTP,
		git:  deps.Git,
		ws:   deps.WorkspaceDir,
		log:  deps.Logger,
	}
	if p.list == nil {
		p.list = creds.Read
	}
	switch c := creds.Read.(type) {
	case auth.TokenSource:
		p.readToken = c
	case auth.SSHSource:
		s := c.SSH()
		p.readSSH = &s
	default:
		return nil, fmt.Errorf("github: auth method %q cannot read code: %w", creds.Read.Method(), vcs.ErrUnsupported)
	}
	u, _ := url.Parse(p.api) // validated
	p.host = u.Host
	if strings.EqualFold(p.host, "api.github.com") {
		p.host = "github.com"
	}
	p.web = u.Scheme + "://" + p.host
	if p.ws == "" {
		p.ws = filepath.Join(os.TempDir(), "heimdall-repos")
	}
	if p.log == nil {
		p.log = slog.New(slog.DiscardHandler)
	}
	p.log = p.log.With("component", "vcs", "plugin", Name)
	return p, nil
}

// Name implements vcs.Provider.
func (p *Provider) Name() string { return Name }

var (
	validName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	shaRe     = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
)

// checkName rejects owner/repo names that could escape the workspace dir.
func checkName(what, s string) error {
	if !validName.MatchString(s) || s == "." || s == ".." {
		return fmt.Errorf("github: invalid %s %q", what, s)
	}
	return nil
}

func isSHA(s string) bool { return shaRe.MatchString(s) }

// cleanPath validates a repo-relative path.
func cleanPath(p string) (string, error) {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") || strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("github: invalid path %q", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", fmt.Errorf("github: invalid path %q", p)
		}
	}
	return p, nil
}

// repoDir is <workspace>/<host>/<owner>/<name> (suffix ".git" for mirrors).
func (p *Provider) repoDir(owner, name string) string {
	return filepath.Join(p.ws, strings.ReplaceAll(p.host, ":", "_"), owner, name)
}
