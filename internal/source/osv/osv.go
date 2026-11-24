// Package osv is the OSV.dev vulnerability source.
//
// It sends every package of a run to POST /v1/querybatch (≤1000 queries per
// request, following next_page_token per query), then fetches each matched
// record with GET /v1/vulns/{id}. Records are immutable for a given
// "modified" timestamp, so details are cached by id+modified.
//
// Go versions are sent without the "v" prefix, as OSV's Go ecosystem stores
// them ("1.2.3", "0.0.0-2021…-abc"); the Go standard library and toolchain are
// queried as OSV packages "stdlib" / "toolchain" with the bare Go release
// number ("1.22.1", not "go1.22.1"), which is how the Go vulnerability
// database publishes their ranges.
package osv

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
	"github.com/hungnm98/heimdall-cve/internal/source"
)

// Name is the source name.
const Name = "osv"

// MaxBatch is the OSV querybatch limit.
const MaxBatch = 1000

func init() { source.Vuln.Register(Name, New) }

// Config is the plugin's config block (`sources.osv`).
type Config struct {
	BaseURL     string        `mapstructure:"base_url"`    // default https://api.osv.dev
	BatchSize   int           `mapstructure:"batch_size"`  // queries per querybatch, 1..1000 (default 1000)
	Concurrency int           `mapstructure:"concurrency"` // parallel detail fetches (default 8)
	CacheTTL    time.Duration `mapstructure:"cache_ttl"`   // detail cache TTL (default 720h; records are keyed by modified)
	// AliasSeverity fills the severity of advisories that carry none (most
	// Go vulndb GO-* records) from their GHSA or CVE alias records (default true).
	AliasSeverity *bool `mapstructure:"alias_severity"`
}

// Validate implements plugin.Validator.
func (c *Config) Validate() error {
	if _, err := url.ParseRequestURI(c.BaseURL); err != nil {
		return fmt.Errorf("base_url: %w", err)
	}
	if c.BatchSize < 1 || c.BatchSize > MaxBatch {
		return fmt.Errorf("batch_size must be in 1..%d", MaxBatch)
	}
	if c.Concurrency < 1 {
		return errors.New("concurrency must be > 0")
	}
	if c.CacheTTL < 0 {
		return errors.New("cache_ttl must be >= 0")
	}
	return nil
}

// Source implements source.VulnSource and source.HealthChecker.
type Source struct {
	cfg      Config
	http     *httpx.Client
	cache    *httpx.Cache
	inflight inflight
}

var (
	_ source.VulnSource    = (*Source)(nil)
	_ source.HealthChecker = (*Source)(nil)
)

// New is the registry factory.
func New(raw plugin.Config, deps plugin.Deps) (source.VulnSource, error) {
	cfg := Config{BaseURL: "https://api.osv.dev", BatchSize: MaxBatch, Concurrency: 8, CacheTTL: 720 * time.Hour}
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("osv: %w", err)
	}
	if deps.HTTP == nil {
		return nil, errors.New("osv: deps.HTTP is required")
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return &Source{cfg: cfg, http: deps.HTTP, cache: deps.Cache}, nil
}

func (s *Source) Name() string { return Name }

func (s *Source) Supports(eco model.Ecosystem) bool { _, ok := ecosystems[eco]; return ok }

// Health queries a package with no known vulnerabilities.
func (s *Source) Health(ctx context.Context) error {
	var out batchResponse
	q := batchRequest{Queries: []batchQuery{{Package: osvPackage{Name: "heimdall-health-probe", Ecosystem: "npm"}, Version: "0.0.0"}}}
	return s.http.PostJSON(ctx, s.cfg.BaseURL+"/v1/querybatch", nil, q, &out)
}

// queryOf maps a package to its OSV query; ok is false when it cannot be queried.
func queryOf(p model.Package) (batchQuery, bool) {
	eco, ok := ecosystems[p.Ecosystem]
	if !ok || p.Name == "" || p.Version == "" {
		return batchQuery{}, false
	}
	v := p.Version
	if p.Ecosystem == model.EcosystemGo {
		v = strings.TrimPrefix(v, "v")
		if p.Name == "stdlib" || p.Name == "toolchain" {
			v = strings.TrimPrefix(v, "go")
		}
	}
	return batchQuery{Package: osvPackage{Name: p.Name, Ecosystem: eco}, Version: v}, true
}

// Query implements source.VulnSource. Withdrawn records are skipped; the
// result is sorted by ID and lists each record once.
func (s *Source) Query(ctx context.Context, pkgs []model.Package) ([]model.Advisory, error) {
	if len(pkgs) == 0 {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	seen := map[batchQuery]bool{}
	var queries []batchQuery
	for _, p := range pkgs {
		if q, ok := queryOf(p); ok && !seen[q] {
			seen[q] = true
			queries = append(queries, q)
		}
	}
	modified, err := s.queryBatches(ctx, queries)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(modified))
	for id := range modified {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	vulns, err := s.fetchAll(ctx, ids, modified)
	if err != nil {
		return nil, err
	}
	out := make([]model.Advisory, 0, len(vulns))
	for _, v := range vulns {
		if v.Withdrawn != nil {
			continue
		}
		out = append(out, toAdvisory(v, Name))
	}
	if s.cfg.AliasSeverity == nil || *s.cfg.AliasSeverity {
		if err := s.aliasSeverity(ctx, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// aliasSeverity fills Severity/CVSS of advisories that have none from their
// alias records, GHSA first (best severity data), then CVE. A missing alias
// (404) is cached as empty so it is not fetched again on every run.
func (s *Source) aliasSeverity(ctx context.Context, advs []model.Advisory) error {
	type job struct {
		idx     int
		aliases []string
	}
	// Aliases returned by the same query are used as they are: no fetch.
	known := map[string]model.Advisory{}
	for _, a := range advs {
		if a.Severity != model.SeverityUnknown {
			known[a.ID] = a
		}
	}
	var jobs []job
	for i, a := range advs {
		if a.Severity != model.SeverityUnknown || a.CVSSScore > 0 {
			continue
		}
		if k, ok := firstKnown(a.Aliases, known); ok {
			advs[i].Severity, advs[i].CVSSVector, advs[i].CVSSScore = k.Severity, k.CVSSVector, k.CVSSScore
			continue
		}
		var ghsa, cve []string
		for _, al := range a.Aliases {
			switch {
			case strings.HasPrefix(al, "GHSA-"):
				ghsa = append(ghsa, al)
			case strings.HasPrefix(al, "CVE-"):
				cve = append(cve, al)
			}
		}
		if cands := append(ghsa, cve...); len(cands) > 0 {
			jobs = append(jobs, job{i, cands})
		}
	}
	if len(jobs) == 0 {
		return nil
	}
	sem := make(chan struct{}, s.cfg.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	for _, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(j job) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, al := range j.aliases {
				v, err := s.fetchAlias(ctx, al)
				if err != nil {
					mu.Lock()
					if firstErr == nil && ctx.Err() != nil {
						firstErr = ctx.Err()
					}
					mu.Unlock()
					return // a failing alias lookup only leaves the severity unknown
				}
				if v.ID == "" {
					continue
				}
				alias := toAdvisory(v, Name)
				if alias.Severity == model.SeverityUnknown {
					continue
				}
				mu.Lock()
				a := &advs[j.idx]
				a.Severity, a.CVSSVector, a.CVSSScore = alias.Severity, alias.CVSSVector, alias.CVSSScore
				mu.Unlock()
				return
			}
		}(j)
	}
	wg.Wait()
	return firstErr
}

func firstKnown(aliases []string, known map[string]model.Advisory) (model.Advisory, bool) {
	for _, prefix := range []string{"GHSA-", "CVE-"} {
		for _, al := range aliases {
			if k, ok := known[al]; ok && strings.HasPrefix(al, prefix) {
				return k, true
			}
		}
	}
	return model.Advisory{}, false
}

// fetchAlias fetches an alias record by id (no modified stamp is known),
// caching 404s as an empty record.
func (s *Source) fetchAlias(ctx context.Context, id string) (osvVuln, error) {
	key := "osv:alias:" + id
	b, err := s.inflight.do(key, func() ([]byte, error) {
		return s.cache.Fetch(ctx, key, s.cfg.CacheTTL, func(ctx context.Context) ([]byte, error) {
			var raw json.RawMessage
			err := s.http.GetJSON(ctx, s.cfg.BaseURL+"/v1/vulns/"+url.PathEscape(id), nil, &raw)
			var se *httpx.StatusError
			if errors.As(err, &se) && se.Code == http.StatusNotFound {
				return []byte("{}"), nil
			}
			if err != nil {
				return nil, fmt.Errorf("osv alias %s: %w", id, err)
			}
			return raw, nil
		})
	})
	if err != nil {
		return osvVuln{}, err
	}
	var v osvVuln
	if err := json.Unmarshal(b, &v); err != nil {
		return osvVuln{}, fmt.Errorf("osv alias %s: decode: %w", id, err)
	}
	return v, nil
}

// queryBatches runs querybatch over all queries, following next_page_token,
// and returns matched vuln IDs with their modified timestamps.
func (s *Source) queryBatches(ctx context.Context, queries []batchQuery) (map[string]string, error) {
	found := map[string]string{}
	pending := queries
	for len(pending) > 0 {
		var next []batchQuery
		for start := 0; start < len(pending); start += s.cfg.BatchSize {
			batch := pending[start:min(start+s.cfg.BatchSize, len(pending))]
			var resp batchResponse
			if err := s.http.PostJSON(ctx, s.cfg.BaseURL+"/v1/querybatch", nil, batchRequest{Queries: batch}, &resp); err != nil {
				return nil, fmt.Errorf("osv querybatch: %w", err)
			}
			if len(resp.Results) != len(batch) {
				return nil, fmt.Errorf("osv querybatch: %d results for %d queries", len(resp.Results), len(batch))
			}
			for i, r := range resp.Results {
				for _, v := range r.Vulns {
					if v.ID != "" && v.Modified >= found[v.ID] {
						found[v.ID] = v.Modified
					}
				}
				if r.NextPageToken != "" {
					q := batch[i]
					q.PageToken = r.NextPageToken
					next = append(next, q)
				}
			}
		}
		pending = next
	}
	return found, nil
}

// fetchAll fetches details with bounded concurrency; the first error cancels the rest.
func (s *Source) fetchAll(ctx context.Context, ids []string, modified map[string]string) ([]osvVuln, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	out := make([]osvVuln, len(ids))
	sem := make(chan struct{}, s.cfg.Concurrency)
	var (
		wg       sync.WaitGroup
		errOnce  sync.Once
		firstErr error
	)
	for i, id := range ids {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			v, err := s.fetch(ctx, id, modified[id])
			if err != nil {
				errOnce.Do(func() { firstErr = err; cancel() })
				return
			}
			out[i] = v
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// fetch returns one record, from the cache when id+modified was seen before.
// Concurrent fetches of the same key share one request.
func (s *Source) fetch(ctx context.Context, id, modified string) (osvVuln, error) {
	key := "osv:vuln:" + id + "@" + modified
	b, err := s.inflight.do(key, func() ([]byte, error) {
		return s.cache.Fetch(ctx, key, s.cfg.CacheTTL, func(ctx context.Context) ([]byte, error) {
			var raw json.RawMessage
			if err := s.http.GetJSON(ctx, s.cfg.BaseURL+"/v1/vulns/"+url.PathEscape(id), nil, &raw); err != nil {
				return nil, fmt.Errorf("osv vuln %s: %w", id, err)
			}
			return raw, nil
		})
	})
	if err != nil {
		return osvVuln{}, err
	}
	var v osvVuln
	if err := json.Unmarshal(b, &v); err != nil {
		return osvVuln{}, fmt.Errorf("osv vuln %s: decode: %w", id, err)
	}
	if v.ID == "" {
		v.ID = id
	}
	return v, nil
}
