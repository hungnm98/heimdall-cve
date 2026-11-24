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
	return out, nil
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
