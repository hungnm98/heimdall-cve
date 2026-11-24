// Package config loads Heimdall's YAML or JSON config, applies defaults and
// HEIMDALL_* env overrides, and validates cross-references. Plugin-specific
// options are kept raw (plugin.Config) and decoded by the plugin itself.
package config

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/secret"
	"github.com/spf13/viper"
)

// Config is the whole config file.
type Config struct {
	AuthProfiles   map[string]Plugin `mapstructure:"auth_profiles"`
	Targets        []Target          `mapstructure:"targets"`
	Ecosystems     []string          `mapstructure:"ecosystems"` // empty = every ecosystem compiled in (multi-language repos)
	PrivateModules []string          `mapstructure:"private_modules"`
	SkipPaths      []string          `mapstructure:"skip_paths"`
	Sources        map[string]Plugin `mapstructure:"sources"`
	Notify         map[string]Plugin `mapstructure:"notify"`
	Report         ReportConfig      `mapstructure:"report"`
	Policy         Policy            `mapstructure:"policy"`
	Store          Plugin            `mapstructure:"store"`
	Cache          CacheConfig       `mapstructure:"cache"`
	Concurrency    Concurrency       `mapstructure:"concurrency"`
	Workspace      Workspace         `mapstructure:"workspace"`
	Server         Server            `mapstructure:"server"`
	Jobs           Plugin            `mapstructure:"jobs"` // queue backend: inline | asynq
	Secrets        SecretsConfig     `mapstructure:"secrets"`
	MCP            MCPConfig         `mapstructure:"mcp"`
}

// MCPConfig controls what AI agents may do through `heimdall mcp`.
// Everything that writes is off by default.
type MCPConfig struct {
	AllowAgentWrites bool   `mapstructure:"allow_agent_writes"` // submit_advisory / submit_analysis
	AllowNotify      bool   `mapstructure:"allow_notify"`       // notify_user
	AllowScan        bool   `mapstructure:"allow_scan"`         // scan_target / scan_repo (queue jobs)
	NotifyDailyLimit int    `mapstructure:"notify_daily_limit"`
	Listen           string `mapstructure:"listen"` // streamable HTTP transport address
}

// Workspace is where repo content is cached between scans: git mirrors (SSH
// mode, checkouts) and manifests fetched through the API, keyed by commit SHA.
// A repo whose HEAD did not move is never cloned or downloaded again.
type Workspace struct {
	Dir        string        `mapstructure:"dir"`
	PruneAfter time.Duration `mapstructure:"prune_after"` // drop mirrors of repos not scanned for this long
}

// Server configures `heimdall serve`.
type Server struct {
	Listen            string `mapstructure:"listen"`
	TrustedUserHeader string `mapstructure:"trusted_user_header"` // e.g. X-Forwarded-Email, set by an SSO proxy; used for audit
	PublicURL         string `mapstructure:"public_url"`          // e.g. https://heimdall.internal, for links in notifications
}

// SecretsConfig locates the master key (KEK) that encrypts secrets entered in the UI.
type SecretsConfig struct {
	MasterKeyEnv  string `mapstructure:"master_key_env"`
	MasterKeyFile string `mapstructure:"master_key_file"`
}

// Plugin is a config block that selects a plugin by type and carries its own
// options. For maps (sources, notify, auth_profiles) the key is the instance
// name and Type defaults to the key, so several instances of one plugin can
// coexist (e.g. two Slack webhooks for two channels).
type Plugin struct {
	Type    string        `mapstructure:"type"`
	Enabled *bool         `mapstructure:"enabled"` // nil = enabled
	Options plugin.Config `mapstructure:",remain"`
}

// IsEnabled reports whether the block is enabled (default true).
func (p Plugin) IsEnabled() bool { return p.Enabled == nil || *p.Enabled }

// TypeOr returns Type, or name when Type is empty.
func (p Plugin) TypeOr(name string) string {
	if p.Type != "" {
		return p.Type
	}
	return name
}

// Target is one `targets` entry.
type Target struct {
	Kind     string   `mapstructure:"kind"`     // org | user | repo
	Provider string   `mapstructure:"provider"` // default github
	BaseURL  string   `mapstructure:"base_url"`
	Name     string   `mapstructure:"name"` // org/user login
	URL      string   `mapstructure:"url"`  // kind=repo
	Branch   string   `mapstructure:"branch"`
	Auth     string   `mapstructure:"auth"`
	ListAuth string   `mapstructure:"list_auth"`
	Repos    []string `mapstructure:"repos"` // static repo names (SSH without list_auth)
	Filters  Filters  `mapstructure:"filters"`
}

// Filters narrows org/user targets.
type Filters struct {
	Include      []string `mapstructure:"include"`
	Exclude      []string `mapstructure:"exclude"`
	Topics       []string `mapstructure:"topics"`
	SkipArchived *bool    `mapstructure:"skip_archived"` // default true
	SkipForks    *bool    `mapstructure:"skip_forks"`    // default true
	SkipEmpty    *bool    `mapstructure:"skip_empty"`    // default true
	MaxRepos     int      `mapstructure:"max_repos"`
}

// ReportConfig selects report formats and the output dir.
type ReportConfig struct {
	Formats []string `mapstructure:"formats"`
	Dir     string   `mapstructure:"dir"`
}

// Policy holds severity thresholds and SLA.
type Policy struct {
	SLADays          map[string]int `mapstructure:"sla_days"`
	FailOn           string         `mapstructure:"fail_on"`
	IgnoreDevDeps    bool           `mapstructure:"ignore_dev_dependencies"`
	SuppressionsFile string         `mapstructure:"suppressions_file"`
	EOLWarningDays   int            `mapstructure:"eol_warning_days"`
}

// CacheConfig configures the on-disk cache.
type CacheConfig struct {
	Dir string        `mapstructure:"dir"`
	TTL time.Duration `mapstructure:"ttl"`
}

// Concurrency limits.
type Concurrency struct {
	Repos       int `mapstructure:"repos"`
	HTTPPerHost int `mapstructure:"http_per_host"`
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("skip_paths", []string{"node_modules/", "vendor/", "testdata/", ".git/", "examples/"})
	v.SetDefault("report.formats", []string{"md", "json"})
	v.SetDefault("report.dir", "reports")
	v.SetDefault("policy.sla_days", map[string]int{"CRITICAL": 7, "HIGH": 30, "MEDIUM": 90})
	v.SetDefault("policy.suppressions_file", ".heimdall-ignore.yaml")
	v.SetDefault("policy.eol_warning_days", 90)
	v.SetDefault("store.type", "postgres")
	v.SetDefault("cache.dir", "~/.cache/heimdall")
	v.SetDefault("cache.ttl", "24h")
	v.SetDefault("concurrency.repos", 8)
	v.SetDefault("concurrency.http_per_host", 4)
	v.SetDefault("workspace.dir", "~/.cache/heimdall/repos")
	v.SetDefault("workspace.prune_after", "720h")
	v.SetDefault("server.listen", "127.0.0.1:8080")
	v.SetDefault("jobs.type", "inline")
	v.SetDefault("secrets.master_key_env", "HEIMDALL_MASTER_KEY")
	v.SetDefault("mcp.notify_daily_limit", 20)
	v.SetDefault("mcp.listen", "127.0.0.1:8090")
}

// Load reads a config file (.yaml, .yml or .json). An empty path searches
// ./heimdall.{yaml,yml,json} then ~/.config/heimdall/. HEIMDALL_<KEY> env vars
// override scalar keys that have a value or default (HEIMDALL_CACHE_TTL, HEIMDALL_CONCURRENCY_REPOS...).
func Load(file string) (*Config, error) {
	v := viper.New()
	setDefaults(v)
	v.SetEnvPrefix("HEIMDALL")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	if file != "" {
		v.SetConfigFile(secret.ExpandHome(file))
	} else {
		v.SetConfigName("heimdall")
		v.AddConfigPath(".")
		v.AddConfigPath(secret.ExpandHome("~/.config/heimdall"))
	}
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	err := v.UnmarshalExact(&c, func(dc *mapstructure.DecoderConfig) {
		dc.DecodeHook = mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
		)
	})
	if err != nil {
		return nil, fmt.Errorf("parse config %s: %w", v.ConfigFileUsed(), err)
	}
	keepEmptyBlocks(v, &c)
	c.Cache.Dir = secret.ExpandHome(c.Cache.Dir)
	c.Workspace.Dir = secret.ExpandHome(c.Workspace.Dir)
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", v.ConfigFileUsed(), err)
	}
	return &c, nil
}

// Validate checks values and cross-references. It reports every problem at once.
func (c *Config) Validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	for name, p := range c.AuthProfiles {
		if p.Type == "" {
			bad("auth_profiles.%s: type is required (token | app | ssh)", name)
		}
	}
	for i, t := range c.Targets {
		where := fmt.Sprintf("targets[%d]", i)
		switch model.TargetKind(t.Kind) {
		case model.TargetOrg, model.TargetUser:
			if t.Name == "" {
				bad("%s: name is required for kind %s", where, t.Kind)
			}
		case model.TargetRepo:
			if _, err := model.ParseRepoURL(t.URL); err != nil {
				bad("%s: %v", where, err)
			}
		default:
			bad("%s: kind must be org, user or repo (got %q)", where, t.Kind)
		}
		if t.Auth == "" {
			bad("%s: auth profile is required", where)
		} else if _, ok := c.AuthProfiles[t.Auth]; !ok {
			bad("%s: unknown auth profile %q", where, t.Auth)
		}
		if t.ListAuth != "" {
			if _, ok := c.AuthProfiles[t.ListAuth]; !ok {
				bad("%s: unknown list_auth profile %q", where, t.ListAuth)
			}
		}
		for _, g := range append(append([]string{}, t.Filters.Include...), t.Filters.Exclude...) {
			if _, err := path.Match(g, ""); err != nil {
				bad("%s: bad glob %q", where, g)
			}
		}
	}
	for k := range c.Policy.SLADays {
		if model.ParseSeverity(k) == model.SeverityUnknown {
			bad("policy.sla_days: unknown severity %q", k)
		}
	}
	if c.Policy.FailOn != "" && model.ParseSeverity(c.Policy.FailOn) == model.SeverityUnknown {
		bad("policy.fail_on: unknown severity %q", c.Policy.FailOn)
	}
	if c.Cache.TTL <= 0 {
		bad("cache.ttl must be > 0")
	}
	if c.Workspace.Dir == "" || c.Workspace.PruneAfter <= 0 {
		bad("workspace.dir and workspace.prune_after are required")
	}
	if c.Concurrency.Repos <= 0 || c.Concurrency.HTTPPerHost <= 0 {
		bad("concurrency values must be > 0")
	}
	return errors.Join(errs...)
}

// ModelTargets converts config targets into model.Target values.
func (c *Config) ModelTargets() []model.Target {
	out := make([]model.Target, 0, len(c.Targets))
	for _, t := range c.Targets {
		mt := model.Target{
			Kind:     model.TargetKind(t.Kind),
			Provider: t.Provider,
			BaseURL:  t.BaseURL,
			Owner:    t.Name,
			Branch:   t.Branch,
			Auth:     t.Auth,
			ListAuth: t.ListAuth,
			Repos:    t.Repos,
			Filter: model.RepoFilter{
				Include:      t.Filters.Include,
				Exclude:      t.Filters.Exclude,
				Topics:       t.Filters.Topics,
				SkipArchived: boolOr(t.Filters.SkipArchived, true),
				SkipForks:    boolOr(t.Filters.SkipForks, true),
				SkipEmpty:    boolOr(t.Filters.SkipEmpty, true),
				MaxRepos:     t.Filters.MaxRepos,
			},
		}
		if mt.Provider == "" {
			mt.Provider = "github"
		}
		if mt.ListAuth == "" {
			mt.ListAuth = mt.Auth
		}
		if mt.Kind == model.TargetRepo {
			u, _ := model.ParseRepoURL(t.URL) // validated
			mt.Owner, mt.Name = u.Owner, u.Name
		}
		out = append(out, mt)
	}
	return out
}

// Summary is a redacted, human-readable view for `heimdall config validate`.
// Plugin options are listed by key only: values may reference secrets.
func (c *Config) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "auth profiles:\n")
	for _, n := range sortedKeys(c.AuthProfiles) {
		fmt.Fprintf(&b, "  - %s (type %s) options: %s\n", n, c.AuthProfiles[n].Type, keys(c.AuthProfiles[n].Options))
	}
	fmt.Fprintf(&b, "targets:\n")
	for _, t := range c.ModelTargets() {
		branch := t.Branch
		if branch == "" {
			branch = "<default>"
		}
		fmt.Fprintf(&b, "  - %s via %s (auth %s, list %s, branch %s)\n", t, t.Provider, t.Auth, t.ListAuth, branch)
	}
	fmt.Fprintf(&b, "ecosystems: %s\n", strings.Join(c.Ecosystems, ", "))
	for _, section := range []struct {
		name string
		m    map[string]Plugin
	}{{"sources", c.Sources}, {"notify", c.Notify}} {
		fmt.Fprintf(&b, "%s:\n", section.name)
		for _, n := range sortedKeys(section.m) {
			p := section.m[n]
			fmt.Fprintf(&b, "  - %s (type %s, enabled %v)\n", n, p.TypeOr(n), p.IsEnabled())
		}
	}
	fmt.Fprintf(&b, "store: %s\ncache: %s (ttl %s)\nworkspace: %s (prune after %s)\njobs: %s\nserver: %s\n",
		c.Store.Type, filepath.Clean(c.Cache.Dir), c.Cache.TTL, filepath.Clean(c.Workspace.Dir), c.Workspace.PruneAfter,
		c.Jobs.Type, c.Server.Listen)
	return b.String()
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func keys(m plugin.Config) string {
	if len(m) == 0 {
		return "-"
	}
	return strings.Join(sortedKeys(m), ",")
}

// Exists reports whether a config file exists at p.
func Exists(p string) bool {
	_, err := os.Stat(secret.ExpandHome(p))
	return err == nil
}

// DefaultSources are enabled when the config file has no `sources` section:
// a scanner with no vulnerability source would silently find nothing.
var DefaultSources = []string{"osv", "endoflife", "kev", "epss"}

// keepEmptyBlocks restores plugin blocks written as `name: {}`: viper drops
// keys whose value is an empty map, which silently disabled such plugins
// (e.g. `sources: { osv: {} }` ran no source at all).
func keepEmptyBlocks(v *viper.Viper, c *Config) {
	restore := func(key string, m *map[string]Plugin) {
		raw, ok := v.Get(key).(map[string]any)
		if !ok {
			return
		}
		for name := range raw {
			if *m == nil {
				*m = map[string]Plugin{}
			}
			if _, ok := (*m)[name]; !ok {
				(*m)[name] = Plugin{}
			}
		}
	}
	restore("sources", &c.Sources)
	restore("notify", &c.Notify)
	restore("auth_profiles", &c.AuthProfiles)
	if !v.InConfig("sources") {
		c.Sources = map[string]Plugin{}
		for _, name := range DefaultSources {
			c.Sources[name] = Plugin{}
		}
	}
}
