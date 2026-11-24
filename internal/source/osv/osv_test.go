package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/httpx"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/source"
	"github.com/hungnm98/heimdall-cve/internal/source/sourcetest"
)

// fakeOSV serves testdata/querybatch.json and testdata/vulns/<id>.json.
type fakeOSV struct {
	t     *testing.T
	pages map[string][]batchResult

	mu          sync.Mutex
	batchSizes  []int
	pageTokens  []string
	detailCalls map[string]int
	failBatch   bool
}

func newFakeOSV(t *testing.T) (*fakeOSV, *httptest.Server) {
	t.Helper()
	b, err := os.ReadFile("testdata/querybatch.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	f := &fakeOSV{t: t, pages: map[string][]batchResult{}, detailCalls: map[string]int{}}
	for k, v := range raw {
		if strings.HasPrefix(k, "_") {
			continue
		}
		var pages []batchResult
		if err := json.Unmarshal(v, &pages); err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		f.pages[k] = pages
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

// with runs fn under the fake's lock: tests read and tweak the fake through it.
func (f *fakeOSV) with(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

func (f *fakeOSV) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock() // requests are served one at a time
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.batchSizes = append(f.batchSizes, len(req.Queries))
		if f.failBatch {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if len(req.Queries) > MaxBatch {
			http.Error(w, "too many queries", http.StatusBadRequest)
			return
		}
		resp := batchResponse{Results: make([]batchResult, len(req.Queries))}
		for i, q := range req.Queries {
			page := 0
			if q.PageToken != "" {
				f.pageTokens = append(f.pageTokens, q.PageToken)
				fmt.Sscanf(q.PageToken, "page-%d", &page)
			}
			if pages := f.pages[q.Package.Ecosystem+"|"+q.Package.Name+"|"+q.Version]; page < len(pages) {
				resp.Results[i] = pages[page]
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		f.detailCalls[id]++
		b, err := os.ReadFile(filepath.Join("testdata", "vulns", id+".json"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	default:
		http.NotFound(w, r)
	}
}

func newSource(t *testing.T, srv *httptest.Server, cache *httpx.Cache, opts plugin.Config) *Source {
	t.Helper()
	if opts == nil {
		opts = plugin.Config{}
	}
	opts["base_url"] = srv.URL
	s, err := New(opts, plugin.Deps{HTTP: httpx.New(httpx.Options{PerHost: 16}), Cache: cache})
	if err != nil {
		t.Fatal(err)
	}
	return s.(*Source)
}

func TestRegistered(t *testing.T) {
	if _, err := source.Vuln.Get(Name); err != nil {
		t.Fatal(err)
	}
}

func TestContract(t *testing.T) {
	_, srv := newFakeOSV(t)
	s := newSource(t, srv, nil, nil)
	sourcetest.RunVuln(t, s, []sourcetest.VulnCase{
		{
			Name:     "go module",
			Packages: []model.Package{model.NewPackage(model.EcosystemGo, "google.golang.org/protobuf", "v1.32.0")},
			WantIDs:  []string{"GO-2024-2611", "GHSA-8r3f-844c-mc37", "CVE-2024-24786"},
		},
		{
			Name:     "go stdlib",
			Packages: []model.Package{model.NewPackage(model.EcosystemGo, "stdlib", "go1.22.1")},
			WantIDs:  []string{"GO-2024-2887", "CVE-2024-24790"},
		},
		{
			Name: "npm and malicious",
			Packages: []model.Package{
				model.NewPackage(model.EcosystemNPM, "lodash", "4.17.15"),
				model.NewPackage(model.EcosystemNPM, "evil-helper", "1.0.1"),
			},
			WantIDs: []string{"GHSA-p6mc-m468-83gw", "CVE-2020-8203", "MAL-2024-1234"},
		},
		{
			Name:     "rubygems",
			Packages: []model.Package{model.NewPackage(model.EcosystemRubyGems, "rack", "2.2.8")},
			WantIDs:  []string{"GHSA-22f2-v57c-j9cx"},
		},
	})
}

func byID(advs []model.Advisory) map[string]model.Advisory {
	m := map[string]model.Advisory{}
	for _, a := range advs {
		m[a.ID] = a
	}
	return m
}

func TestMapping(t *testing.T) {
	_, srv := newFakeOSV(t)
	s := newSource(t, srv, nil, nil)
	advs, err := s.Query(context.Background(), []model.Package{
		model.NewPackage(model.EcosystemGo, "google.golang.org/protobuf", "v1.32.0"),
		model.NewPackage(model.EcosystemGo, "stdlib", "go1.22.1"),
		model.NewPackage(model.EcosystemNPM, "lodash", "4.17.15"),
		model.NewPackage(model.EcosystemNPM, "evil-helper", "1.0.1"),
		model.NewPackage(model.EcosystemRubyGems, "rack", "2.2.8"),
		model.NewPackage("pypi", "requests", "2.0.0"), // unsupported: ignored
	})
	if err != nil {
		t.Fatal(err)
	}
	m := byID(advs)
	if len(m) != 6 {
		t.Fatalf("got %d advisories: %v", len(m), m)
	}

	ghsa := m["GHSA-8r3f-844c-mc37"]
	if ghsa.CVSSScore != 5.9 || ghsa.Severity != model.SeverityMedium || !strings.HasPrefix(ghsa.CVSSVector, "CVSS:3.1/") {
		t.Errorf("GHSA cvss = %v %s %s", ghsa.CVSSScore, ghsa.Severity, ghsa.CVSSVector)
	}
	if ghsa.Sources[0] != Name || !ghsa.Verified || len(ghsa.References) != 2 || ghsa.Published.IsZero() || ghsa.Modified.IsZero() {
		t.Errorf("GHSA metadata = %+v", ghsa)
	}

	// Go vulndb records carry no severity: it comes from the GHSA alias.
	goAdv := m["GO-2024-2611"]
	if goAdv.Severity != model.SeverityMedium || goAdv.CVSSScore != 5.9 {
		t.Errorf("GO severity from alias = %s %v", goAdv.Severity, goAdv.CVSSScore)
	}
	want := []model.VersionRange{{Introduced: "0", Fixed: "1.33.0"}}
	if len(goAdv.Affected) != 1 || fmt.Sprint(goAdv.Affected[0].Ranges) != fmt.Sprint(want) || goAdv.Affected[0].Ecosystem != model.EcosystemGo {
		t.Errorf("GO affected = %+v", goAdv.Affected)
	}

	std := m["GO-2024-2887"]
	wantStd := []model.VersionRange{{Introduced: "0", Fixed: "1.21.11"}, {Introduced: "1.22.0-0", Fixed: "1.22.4"}}
	if fmt.Sprint(std.Affected[0].Ranges) != fmt.Sprint(wantStd) || std.Affected[0].Name != "stdlib" {
		t.Errorf("stdlib affected = %+v", std.Affected)
	}

	lodash := m["GHSA-p6mc-m468-83gw"]
	if lodash.CVSSScore != 7.4 || lodash.Severity != model.SeverityHigh || len(lodash.Affected) != 1 {
		t.Errorf("lodash = %v %s %+v (PyPI entry must be dropped)", lodash.CVSSScore, lodash.Severity, lodash.Affected)
	}

	mal := m["MAL-2024-1234"]
	if !mal.IsMalicious() || len(mal.Affected[0].Versions) != 2 || mal.Severity != model.SeverityUnknown {
		t.Errorf("MAL = %+v", mal)
	}

	rack := m["GHSA-22f2-v57c-j9cx"]
	if !strings.HasPrefix(rack.CVSSVector, "CVSS:4.0/") || rack.CVSSScore != 0 || rack.Severity != model.SeverityMedium {
		t.Errorf("rack cvss4 = %s %v %s (want v4 vector, label severity)", rack.CVSSVector, rack.CVSSScore, rack.Severity)
	}
	if len(rack.Affected[0].Ranges) != 4 {
		t.Errorf("rack ranges = %+v", rack.Affected[0].Ranges)
	}
}

func TestPaginationAndWithdrawn(t *testing.T) {
	f, srv := newFakeOSV(t)
	s := newSource(t, srv, nil, nil)
	advs, err := s.Query(context.Background(), []model.Package{model.NewPackage(model.EcosystemGo, "golang.org/x/net", "v0.15.0")})
	if err != nil {
		t.Fatal(err)
	}
	f.with(func() {
		if fmt.Sprint(f.pageTokens) != "[page-1]" {
			t.Errorf("page tokens = %v", f.pageTokens)
		}
		if f.detailCalls["GHSA-9wd0-wd00-test"] != 1 {
			t.Error("second page was not followed")
		}
	})
	if len(advs) != 1 || advs[0].ID != "GO-2023-2102" {
		t.Errorf("advisories = %+v; want only GO-2023-2102 (withdrawn skipped)", advs)
	}
}

func TestBatchSplitting(t *testing.T) {
	f, srv := newFakeOSV(t)
	s := newSource(t, srv, nil, nil)
	pkgs := make([]model.Package, 0, 2501)
	for i := range 2500 {
		pkgs = append(pkgs, model.NewPackage(model.EcosystemNPM, fmt.Sprintf("pkg-%d", i), "1.0.0"))
	}
	pkgs = append(pkgs, pkgs[0]) // duplicate queries are sent once
	if _, err := s.Query(context.Background(), pkgs); err != nil {
		t.Fatal(err)
	}
	f.with(func() {
		if fmt.Sprint(f.batchSizes) != "[1000 1000 500]" {
			t.Errorf("batch sizes = %v", f.batchSizes)
		}
		f.batchSizes = nil
	})
	small := newSource(t, srv, nil, plugin.Config{"batch_size": 300})
	if _, err := small.Query(context.Background(), pkgs[:700]); err != nil {
		t.Fatal(err)
	}
	f.with(func() {
		if fmt.Sprint(f.batchSizes) != "[300 300 100]" {
			t.Errorf("batch sizes = %v", f.batchSizes)
		}
	})
}

func TestDetailCache(t *testing.T) {
	f, srv := newFakeOSV(t)
	cache, err := httpx.NewCache(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pkgs := []model.Package{model.NewPackage(model.EcosystemGo, "google.golang.org/protobuf", "v1.32.0")}
	for range 2 {
		s := newSource(t, srv, cache, nil) // a new instance: hits must come from deps.Cache
		advs, err := s.Query(context.Background(), pkgs)
		if err != nil || len(advs) != 2 {
			t.Fatalf("advs=%d err=%v", len(advs), err)
		}
	}
	f.with(func() {
		if f.detailCalls["GO-2024-2611"] != 1 || f.detailCalls["GHSA-8r3f-844c-mc37"] != 1 {
			t.Errorf("detail calls = %v; want 1 each (cached)", f.detailCalls)
		}
		if len(f.batchSizes) != 2 {
			t.Errorf("querybatch must not be cached: %v", f.batchSizes)
		}
	})
}

func TestErrors(t *testing.T) {
	f, srv := newFakeOSV(t)
	s := newSource(t, srv, nil, nil)
	f.with(func() { f.failBatch = true })
	if _, err := s.Query(context.Background(), []model.Package{model.NewPackage(model.EcosystemNPM, "lodash", "4.17.15")}); err == nil {
		t.Error("querybatch failure must fail the query")
	}
	f.with(func() {
		f.failBatch = false
		f.pages["npm|ghost|1.0.0"] = []batchResult{{Vulns: []batchVuln{{ID: "GHSA-missing", Modified: "x"}}}}
	})
	if _, err := s.Query(context.Background(), []model.Package{model.NewPackage(model.EcosystemNPM, "ghost", "1.0.0")}); err == nil {
		t.Error("detail failure must fail the query")
	}
	for _, bad := range []plugin.Config{{"batch_size": 1001}, {"concurrency": 0}, {"base_url": "::"}, {"nope": 1}} {
		if _, err := New(bad, plugin.Deps{HTTP: httpx.New(httpx.Options{})}); err == nil {
			t.Errorf("New(%v) accepted invalid config", bad)
		}
	}
}

func TestQueryOf(t *testing.T) {
	for _, c := range []struct {
		p    model.Package
		want string
		ok   bool
	}{
		{model.NewPackage(model.EcosystemGo, "github.com/a/b", "v1.2.3"), "Go|github.com/a/b|1.2.3", true},
		{model.NewPackage(model.EcosystemGo, "github.com/a/b", "v2.0.0+incompatible"), "Go|github.com/a/b|2.0.0+incompatible", true},
		{model.NewPackage(model.EcosystemGo, "github.com/a/b", "v0.0.0-20210101000000-abcdefabcdef"), "Go|github.com/a/b|0.0.0-20210101000000-abcdefabcdef", true},
		{model.NewPackage(model.EcosystemGo, "stdlib", "go1.22.1"), "Go|stdlib|1.22.1", true},
		{model.NewPackage(model.EcosystemGo, "toolchain", "go1.23.0"), "Go|toolchain|1.23.0", true},
		{model.NewPackage(model.EcosystemRubyGems, "rack", "2.2.8"), "RubyGems|rack|2.2.8", true},
		{model.NewPackage(model.EcosystemNPM, "lodash", ""), "", false},
		{model.NewPackage("pypi", "x", "1"), "", false},
	} {
		q, ok := queryOf(c.p)
		got := ""
		if ok {
			got = q.Package.Ecosystem + "|" + q.Package.Name + "|" + q.Version
		}
		if ok != c.ok || got != c.want {
			t.Errorf("queryOf(%+v) = %q %v; want %q %v", c.p, got, ok, c.want, c.ok)
		}
	}
}

func TestInflightDedupesConcurrentFetches(t *testing.T) {
	var g inflight
	release := make(chan struct{})
	calls := 0
	fn := func() ([]byte, error) { calls++; <-release; return []byte("v"), nil }
	const n = 5
	var wg sync.WaitGroup
	results := make([]string, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, _ := g.do("k", fn)
			results[i] = string(b)
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		g.mu.Lock()
		joined := g.dups
		g.mu.Unlock()
		if joined == n-1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d callers joined", joined)
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	wg.Wait()
	if calls != 1 || strings.Join(results, "") != "vvvvv" {
		t.Errorf("calls=%d results=%v", calls, results)
	}
}

func TestAliasSeverity(t *testing.T) {
	f, srv := newFakeOSV(t)
	cache, err := httpx.NewCache(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := newSource(t, srv, cache, nil)
	advs := []model.Advisory{
		{ID: "GO-2024-2611", Aliases: []string{"CVE-2024-24786", "GHSA-8r3f-844c-mc37"}, Severity: model.SeverityUnknown},
		{ID: "GO-2099-0001", Aliases: []string{"CVE-2099-0001"}, Severity: model.SeverityUnknown},
		{ID: "GHSA-x", Aliases: []string{"CVE-2024-24786"}, Severity: model.SeverityHigh},
	}
	for i := 0; i < 2; i++ {
		cp := append([]model.Advisory(nil), advs...)
		if err := s.aliasSeverity(context.Background(), cp); err != nil {
			t.Fatal(err)
		}
		if cp[0].Severity != model.SeverityMedium || cp[0].CVSSScore != 5.9 || cp[0].CVSSVector == "" {
			t.Fatalf("GHSA alias must fill severity: %+v", cp[0])
		}
		if cp[1].Severity != model.SeverityUnknown || cp[2].Severity != model.SeverityHigh {
			t.Fatalf("unknown alias stays unknown, known severity untouched: %+v %+v", cp[1], cp[2])
		}
	}
	f.with(func() {
		if f.detailCalls["GHSA-8r3f-844c-mc37"] != 1 || f.detailCalls["CVE-2099-0001"] != 1 || f.detailCalls["CVE-2024-24786"] != 0 {
			t.Fatalf("aliases must be fetched once (404s cached, GHSA preferred, known severities skipped): %v", f.detailCalls)
		}
	})
}

func TestAliasSeverityBitnami(t *testing.T) {
	f, srv := newFakeOSV(t)
	s := newSource(t, srv, nil, nil)
	advs := []model.Advisory{{ID: "GO-2025-4006", Aliases: []string{"CVE-2025-61725", "BIT-golang-2025-61725"}, Severity: model.SeverityUnknown}}
	if err := s.aliasSeverity(context.Background(), advs); err != nil {
		t.Fatal(err)
	}
	if advs[0].Severity != model.SeverityHigh || advs[0].CVSSScore != 7.5 {
		t.Fatalf("Bitnami alias must score the stdlib advisory: %+v", advs[0])
	}
	f.with(func() {
		if f.detailCalls["CVE-2025-61725"] != 0 {
			t.Fatalf("BIT- is tried before CVE-: %v", f.detailCalls)
		}
	})
}
