// Package epss is an enricher that fills the EPSS score of findings: the
// probability (0–1) that a CVE is exploited in the next 30 days, from the
// FIRST.org EPSS API. Lookups are batched and cached per CVE (misses
// included) for cache_ttl, since scores are recomputed daily.
//
// Config (`sources.epss`):
//
//	base_url: https://api.first.org
//	cache_ttl: 24h
package epss

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/httpx"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/source"
)

// Name is the source name.
const Name = "epss"

// batch is the number of CVEs per request (the API pages at 100 rows).
const batch = 100

func init() { source.Enrichers.Register(Name, New) }

// Config is the plugin's config block.
type Config struct {
	BaseURL  string        `mapstructure:"base_url"`
	CacheTTL time.Duration `mapstructure:"cache_ttl"`
}

// Validate implements plugin.Validator.
func (c *Config) Validate() error {
	if _, err := url.ParseRequestURI(c.BaseURL); err != nil {
		return fmt.Errorf("base_url: %w", err)
	}
	if c.CacheTTL <= 0 {
		return errors.New("cache_ttl must be > 0")
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
	cfg := Config{BaseURL: "https://api.first.org", CacheTTL: 24 * time.Hour}
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("epss: %w", err)
	}
	return &Enricher{cfg: cfg, http: deps.HTTP, cache: deps.Cache}, nil
}

// Name implements source.Enricher.
func (e *Enricher) Name() string { return Name }

// score is one CVE's EPSS (cached as JSON; zero = not scored).
type score struct {
	EPSS       float64 `json:"epss,omitempty"`
	Percentile float64 `json:"percentile,omitempty"`
}

// Enrich implements source.Enricher: a finding gets the highest EPSS among
// its CVE aliases.
func (e *Enricher) Enrich(ctx context.Context, findings []*model.Finding) error {
	seen := map[string]bool{}
	var all []string
	for _, f := range findings {
		if f.Kind != model.KindDependency {
			continue
		}
		for _, id := range source.CVEs(f) {
			if !seen[id] {
				seen[id] = true
				all = append(all, id)
			}
		}
	}
	if len(all) == 0 {
		return nil
	}
	sort.Strings(all)
	scores := map[string]score{}
	var missing []string
	for _, id := range all {
		if s, ok := e.cached(id); ok {
			scores[id] = s
		} else {
			missing = append(missing, id)
		}
	}
	var lastErr error
	for i := 0; i < len(missing); i += batch {
		ids := missing[i:min(i+batch, len(missing))]
		got, err := e.lookup(ctx, ids)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			lastErr = err
			continue
		}
		for _, id := range ids {
			s := got[id] // absent = not scored: cached as a miss
			scores[id] = s
			if b, err := json.Marshal(s); err == nil {
				_ = e.cache.Put(cacheKey(id), b)
			}
		}
	}
	for _, f := range findings {
		if f.Kind != model.KindDependency {
			continue
		}
		for _, id := range source.CVEs(f) {
			if s := scores[id]; s.EPSS > f.EPSS {
				f.EPSS, f.EPSSPercentile = s.EPSS, s.Percentile
			}
		}
	}
	return lastErr
}

func cacheKey(id string) string { return "epss:cve:" + id }

func (e *Enricher) cached(id string) (score, bool) {
	b, ok := e.cache.Get(cacheKey(id), e.cfg.CacheTTL)
	if !ok {
		return score{}, false
	}
	var s score
	if json.Unmarshal(b, &s) != nil {
		return score{}, false
	}
	return s, true
}

type response struct {
	Data []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
	} `json:"data"`
}

func (e *Enricher) lookup(ctx context.Context, ids []string) (map[string]score, error) {
	u := fmt.Sprintf("%s/data/v1/epss?limit=%d&cve=%s", e.cfg.BaseURL, batch, url.QueryEscape(strings.Join(ids, ",")))
	var resp response
	if err := e.http.GetJSON(ctx, u, nil, &resp); err != nil {
		return nil, fmt.Errorf("epss: %w", err)
	}
	out := make(map[string]score, len(resp.Data))
	for _, d := range resp.Data {
		p, err1 := strconv.ParseFloat(d.EPSS, 64)
		q, err2 := strconv.ParseFloat(d.Percentile, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out[d.CVE] = score{EPSS: p, Percentile: q}
	}
	return out, nil
}
