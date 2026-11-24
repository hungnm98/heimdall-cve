// Package kev is an enricher that flags findings whose CVE is in the CISA
// Known Exploited Vulnerabilities catalog: vulnerabilities exploited in the
// wild, which Heimdall ranks above every other finding.
//
// The whole catalog (one JSON file) is downloaded at most once per
// cache_ttl. When a refresh fails, a catalog up to max_stale old is used
// instead, so a CISA outage does not drop KEV flags.
//
// Config (`sources.kev`):
//
//	url: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
//	cache_ttl: 24h
//	max_stale: 720h
package kev

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/httpx"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/source"
)

// Name is the source name.
const Name = "kev"

const cacheKey = "kev:catalog"

func init() { source.Enrichers.Register(Name, New) }

// Config is the plugin's config block.
type Config struct {
	URL      string        `mapstructure:"url"`
	CacheTTL time.Duration `mapstructure:"cache_ttl"`
	MaxStale time.Duration `mapstructure:"max_stale"`
}

// Validate implements plugin.Validator.
func (c *Config) Validate() error {
	if _, err := url.ParseRequestURI(c.URL); err != nil {
		return fmt.Errorf("url: %w", err)
	}
	if c.CacheTTL <= 0 || c.MaxStale < c.CacheTTL {
		return errors.New("cache_ttl must be > 0 and max_stale >= cache_ttl")
	}
	return nil
}

// Enricher implements source.Enricher.
type Enricher struct {
	cfg   Config
	http  *httpx.Client
	cache *httpx.Cache
}

// New is the registry factory.
func New(raw plugin.Config, deps plugin.Deps) (source.Enricher, error) {
	cfg := Config{
		URL:      "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
		CacheTTL: 24 * time.Hour,
		MaxStale: 30 * 24 * time.Hour,
	}
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("kev: %w", err)
	}
	return &Enricher{cfg: cfg, http: deps.HTTP, cache: deps.Cache}, nil
}

// Name implements source.Enricher.
func (e *Enricher) Name() string { return Name }

// Enrich implements source.Enricher: sets InKEV on findings with a CVE in the catalog.
func (e *Enricher) Enrich(ctx context.Context, findings []*model.Finding) error {
	need := false
	for _, f := range findings {
		if f.Kind == model.KindDependency && len(source.CVEs(f)) > 0 {
			need = true
			break
		}
	}
	if !need {
		return nil
	}
	catalog, err := e.catalog(ctx)
	if catalog == nil {
		return err
	}
	for _, f := range findings {
		if f.Kind != model.KindDependency {
			continue
		}
		for _, id := range source.CVEs(f) {
			if catalog[id] {
				f.InKEV = true
				break
			}
		}
	}
	return err // non-nil when a stale catalog was used
}

// catalog returns the set of CVE ids in the catalog, fresh or (on a failed refresh) stale.
func (e *Enricher) catalog(ctx context.Context) (map[string]bool, error) {
	if m, ok := e.cached(e.cfg.CacheTTL); ok {
		return m, nil
	}
	m, err := e.download(ctx)
	if err == nil {
		if b, merr := json.Marshal(m); merr == nil {
			_ = e.cache.Put(cacheKey, b)
		}
		return m, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if stale, ok := e.cached(e.cfg.MaxStale); ok {
		return stale, fmt.Errorf("kev: refresh failed, using a cached catalog: %w", err)
	}
	return nil, fmt.Errorf("kev: %w", err)
}

func (e *Enricher) cached(ttl time.Duration) (map[string]bool, bool) {
	b, ok := e.cache.Get(cacheKey, ttl)
	if !ok {
		return nil, false
	}
	var m map[string]bool
	if json.Unmarshal(b, &m) != nil || len(m) == 0 {
		return nil, false
	}
	return m, true
}

type feed struct {
	Vulnerabilities []struct {
		CVEID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

func (e *Enricher) download(ctx context.Context) (map[string]bool, error) {
	var fd feed
	if err := e.http.GetJSON(ctx, e.cfg.URL, nil, &fd); err != nil {
		return nil, err
	}
	if len(fd.Vulnerabilities) == 0 {
		return nil, errors.New("empty catalog")
	}
	m := make(map[string]bool, len(fd.Vulnerabilities))
	for _, v := range fd.Vulnerabilities {
		if v.CVEID != "" {
			m[v.CVEID] = true
		}
	}
	return m, nil
}
