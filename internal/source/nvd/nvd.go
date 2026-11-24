// Package nvd is an enricher that fills the CVSS score and severity of
// findings that have none, from the NIST National Vulnerability Database
// (API 2.0), looked up by the CVE IDs among a finding's advisory aliases.
//
// NVD rate-limits hard (5 requests per 30 s without an API key, 50 with
// one), so lookups are paced, cached for a week (misses included) and capped
// per run; findings not reached keep UNKNOWN and are filled on later runs.
//
// Config (`sources.nvd`):
//
//	api_key_env: NVD_API_KEY     # optional; raises the rate limit tenfold
//	max_lookups: 200             # uncached CVEs looked up per run
//	cache_ttl: 168h
package nvd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/httpx"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/secret"
	"github.com/hungnm98/heimdall-cve/internal/source"
)

// Name is the source name.
const Name = "nvd"

func init() { source.Enrichers.Register(Name, New) }

// Config is the plugin's config block.
type Config struct {
	BaseURL    string        `mapstructure:"base_url"`
	APIKeyEnv  string        `mapstructure:"api_key_env"`
	APIKeyFile string        `mapstructure:"api_key_file"`
	APIKeyRef  string        `mapstructure:"api_key_ref"`
	MaxLookups int           `mapstructure:"max_lookups"`
	CacheTTL   time.Duration `mapstructure:"cache_ttl"`
	// Interval between requests; default 6.5s without a key, 0.7s with one
	// (NVD: 5 / 50 requests per rolling 30 s window).
	Interval time.Duration `mapstructure:"interval"`
}

// Validate implements plugin.Validator.
func (c *Config) Validate() error {
	if _, err := url.ParseRequestURI(c.BaseURL); err != nil {
		return fmt.Errorf("base_url: %w", err)
	}
	if c.MaxLookups < 0 || c.CacheTTL <= 0 || c.Interval < 0 {
		return errors.New("max_lookups must be >= 0, cache_ttl > 0, interval >= 0")
	}
	return nil
}

// Enricher implements source.Enricher.
type Enricher struct {
	cfg     Config
	http    *httpx.Client
	cache   *httpx.Cache
	secrets secret.Resolver
	sleep   func(context.Context, time.Duration) error

	mu   sync.Mutex
	last time.Time
}

// New is the registry factory.
func New(raw plugin.Config, deps plugin.Deps) (source.Enricher, error) {
	cfg := Config{BaseURL: "https://services.nvd.nist.gov", MaxLookups: 200, CacheTTL: 7 * 24 * time.Hour}
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("nvd: %w", err)
	}
	r := deps.Secrets
	if r == nil {
		r = secret.EnvFile{}
	}
	return &Enricher{cfg: cfg, http: deps.HTTP, cache: deps.Cache, secrets: r, sleep: sleepCtx}, nil
}

// Name implements source.Enricher.
func (e *Enricher) Name() string { return Name }

// metric is what we keep from an NVD record (cached as JSON; empty = no score).
type metric struct {
	Vector   string  `json:"vector,omitempty"`
	Score    float64 `json:"score,omitempty"`
	Severity string  `json:"severity,omitempty"`
}

// Enrich implements source.Enricher: findings without a severity get the
// score of the first of their CVE aliases NVD has scored.
func (e *Enricher) Enrich(ctx context.Context, findings []*model.Finding) error {
	cvesOf := map[*model.Finding][]string{}
	var all []string
	seen := map[string]bool{}
	for _, f := range findings {
		if f.Severity != model.SeverityUnknown || f.CVSSScore > 0 || f.Kind != model.KindDependency {
			continue
		}
		for _, id := range append([]string{f.AdvisoryID}, f.Aliases...) {
			if !strings.HasPrefix(id, "CVE-") {
				continue
			}
			cvesOf[f] = append(cvesOf[f], id)
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
	key, err := e.apiKey(ctx)
	if err != nil {
		return err
	}
	scores := map[string]metric{}
	lookups := 0
	var lastErr error
	for _, id := range all {
		if m, ok := e.cached(id); ok {
			scores[id] = m
			continue
		}
		if lookups >= e.cfg.MaxLookups {
			continue // next run continues where this one stopped
		}
		lookups++
		m, err := e.lookup(ctx, id, key)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			lastErr = err
			continue
		}
		scores[id] = m
	}
	for f, ids := range cvesOf {
		for _, id := range ids {
			if m := scores[id]; m.Score > 0 || m.Severity != "" {
				f.CVSSVector, f.CVSSScore = m.Vector, m.Score
				f.Severity = model.SeverityFromCVSS(m.Score)
				if f.Severity == model.SeverityUnknown {
					f.Severity = model.ParseSeverity(m.Severity)
				}
				f.Sources = appendUnique(f.Sources, Name)
				break
			}
		}
	}
	// Partial results are useful; report the last failure so the run marks
	// the source unhealthy.
	return lastErr
}

func (e *Enricher) apiKey(ctx context.Context) (string, error) {
	ref := secret.Ref{Env: e.cfg.APIKeyEnv, File: e.cfg.APIKeyFile, ID: e.cfg.APIKeyRef}
	if ref.IsZero() {
		return "", nil
	}
	v, err := e.secrets.Resolve(ctx, ref)
	if errors.Is(err, secret.ErrMissing) {
		return "", nil // a key is optional: run at the anonymous rate
	}
	if err != nil {
		return "", fmt.Errorf("nvd api key: %w", err)
	}
	return v, nil
}

func cacheKey(id string) string { return "nvd:cve:" + id }

func (e *Enricher) cached(id string) (metric, bool) {
	b, ok := e.cache.Get(cacheKey(id), e.cfg.CacheTTL)
	if !ok {
		return metric{}, false
	}
	var m metric
	if json.Unmarshal(b, &m) != nil {
		return metric{}, false
	}
	return m, true
}

func (e *Enricher) lookup(ctx context.Context, id, key string) (metric, error) {
	if err := e.pace(ctx, key != ""); err != nil {
		return metric{}, err
	}
	var hdr http.Header
	if key != "" {
		hdr = http.Header{"apiKey": []string{key}}
	}
	var resp nvdResponse
	err := e.http.GetJSON(ctx, e.cfg.BaseURL+"/rest/json/cves/2.0?cveId="+url.QueryEscape(id), hdr, &resp)
	var se *httpx.StatusError
	if errors.As(err, &se) && se.Code == http.StatusNotFound {
		err = nil // unknown CVE: cache the miss
	}
	if err != nil {
		return metric{}, fmt.Errorf("nvd %s: %w", id, err)
	}
	m := resp.best(id)
	if b, err := json.Marshal(m); err == nil {
		_ = e.cache.Put(cacheKey(id), b)
	}
	return m, nil
}

// pace spaces requests to stay under NVD's rolling-window limit.
func (e *Enricher) pace(ctx context.Context, withKey bool) error {
	interval := e.cfg.Interval
	if interval == 0 {
		interval = 6500 * time.Millisecond
		if withKey {
			interval = 700 * time.Millisecond
		}
	}
	e.mu.Lock()
	wait := time.Until(e.last.Add(interval))
	if wait < 0 {
		wait = 0
	}
	e.last = time.Now().Add(wait)
	e.mu.Unlock()
	if wait == 0 {
		return nil
	}
	return e.sleep(ctx, wait)
}

type cvssData struct {
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type cvssMetric struct {
	Type         string   `json:"type"` // Primary (NVD) or Secondary (CNA)
	CVSSData     cvssData `json:"cvssData"`
	BaseSeverity string   `json:"baseSeverity"` // v2 keeps it outside cvssData
}

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID      string `json:"id"`
			Metrics struct {
				V40 []cvssMetric `json:"cvssMetricV40"`
				V31 []cvssMetric `json:"cvssMetricV31"`
				V30 []cvssMetric `json:"cvssMetricV30"`
				V2  []cvssMetric `json:"cvssMetricV2"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// best prefers CVSS v3.1, then v4.0, v3.0, v2; within a version the NVD
// (Primary) score over a CNA (Secondary) one.
func (r nvdResponse) best(id string) metric {
	for _, v := range r.Vulnerabilities {
		if v.CVE.ID != id {
			continue
		}
		m := v.CVE.Metrics
		for _, list := range [][]cvssMetric{m.V31, m.V40, m.V30, m.V2} {
			if len(list) == 0 {
				continue
			}
			pick := list[0]
			for _, c := range list {
				if c.Type == "Primary" {
					pick = c
					break
				}
			}
			sev := pick.CVSSData.BaseSeverity
			if sev == "" {
				sev = pick.BaseSeverity
			}
			return metric{Vector: pick.CVSSData.VectorString, Score: pick.CVSSData.BaseScore, Severity: sev}
		}
	}
	return metric{}
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
