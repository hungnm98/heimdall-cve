package nvd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/httpx"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/source"
)

const recordV31 = `{"vulnerabilities":[{"cve":{"id":"CVE-2024-0001","metrics":{
  "cvssMetricV31":[
    {"source":"cna@example","type":"Secondary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","baseScore":5.3,"baseSeverity":"MEDIUM"}},
    {"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","baseScore":9.8,"baseSeverity":"CRITICAL"}}],
  "cvssMetricV2":[{"type":"Primary","cvssData":{"baseScore":5.0},"baseSeverity":"MEDIUM"}]}}}]}`

const recordV2Only = `{"vulnerabilities":[{"cve":{"id":"CVE-2024-0002","metrics":{
  "cvssMetricV2":[{"type":"Primary","cvssData":{"vectorString":"AV:N/AC:L/Au:N/C:P/I:N/A:N","baseScore":5.0},"baseSeverity":"MEDIUM"}]}}}]}`

const recordUnscored = `{"vulnerabilities":[{"cve":{"id":"CVE-2024-0003","metrics":{}}}]}`

type fakeNVD struct {
	mu    sync.Mutex
	calls map[string]int
	key   string
}

func (f *fakeNVD) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := r.URL.Query().Get("cveId")
	f.calls[id]++
	f.key = r.Header.Get("apiKey")
	switch id {
	case "CVE-2024-0001":
		_, _ = w.Write([]byte(recordV31))
	case "CVE-2024-0002":
		_, _ = w.Write([]byte(recordV2Only))
	case "CVE-2024-0003":
		_, _ = w.Write([]byte(recordUnscored))
	default:
		http.NotFound(w, r)
	}
}

func newEnricher(t *testing.T, srv *httptest.Server, cache *httpx.Cache, opts plugin.Config) *Enricher {
	t.Helper()
	if opts == nil {
		opts = plugin.Config{}
	}
	opts["base_url"] = srv.URL
	opts["interval"] = "1ms"
	e, err := New(opts, plugin.Deps{HTTP: httpx.New(httpx.Options{}), Cache: cache})
	if err != nil {
		t.Fatal(err)
	}
	return e.(*Enricher)
}

func finding(id string, aliases ...string) *model.Finding {
	return &model.Finding{Kind: model.KindDependency, AdvisoryID: id, Aliases: aliases, Severity: model.SeverityUnknown, Sources: []string{"osv"}}
}

func TestRegistered(t *testing.T) {
	if _, err := source.Enrichers.Get(Name); err != nil {
		t.Fatal(err)
	}
}

func TestEnrich(t *testing.T) {
	f := &fakeNVD{calls: map[string]int{}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	cache, err := httpx.NewCache(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_NVD_KEY", "k-123")
	for run := 0; run < 2; run++ {
		e := newEnricher(t, srv, cache, plugin.Config{"api_key_env": "TEST_NVD_KEY"})
		a := finding("GO-2024-1", "CVE-2024-0001")
		b := finding("GO-2024-2", "GHSA-none", "CVE-2024-0002")
		c := finding("GO-2024-3", "CVE-2024-0003", "CVE-2024-0404")
		d := finding("CVE-2024-0001") // shares the CVE with a
		known := &model.Finding{Kind: model.KindDependency, AdvisoryID: "GO-x", Aliases: []string{"CVE-2024-0002"}, Severity: model.SeverityLow}
		if err := e.Enrich(context.Background(), []*model.Finding{a, b, c, d, known}); err != nil {
			t.Fatal(err)
		}
		if a.Severity != model.SeverityCritical || a.CVSSScore != 9.8 || !strings.Contains(a.CVSSVector, "C:H") {
			t.Fatalf("run %d: Primary v3.1 must win: %+v", run, a)
		}
		if a.Sources[len(a.Sources)-1] != Name || d.Severity != model.SeverityCritical {
			t.Fatalf("run %d: source recorded and shared CVE reused: %+v %+v", run, a, d)
		}
		if b.Severity != model.SeverityMedium || b.CVSSScore != 5.0 {
			t.Fatalf("run %d: v2 fallback: %+v", run, b)
		}
		if c.Severity != model.SeverityUnknown || known.Severity != model.SeverityLow {
			t.Fatalf("run %d: unscored stays unknown, known untouched: %+v %+v", run, c, known)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0404"} {
		if f.calls[id] != 1 {
			t.Errorf("%s fetched %d times, want once (hits and misses cached)", id, f.calls[id])
		}
	}
	if f.key != "k-123" {
		t.Errorf("api key header = %q", f.key)
	}
}

func TestMaxLookupsAndPacing(t *testing.T) {
	f := &fakeNVD{calls: map[string]int{}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	e := newEnricher(t, srv, nil, plugin.Config{"max_lookups": 1})
	e.cfg.Interval = 0 // use the default pacing, with a fake clock
	var waits []time.Duration
	e.sleep = func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	a, b := finding("CVE-2024-0001"), finding("CVE-2024-0002")
	if err := e.Enrich(context.Background(), []*model.Finding{a, b}); err != nil {
		t.Fatal(err)
	}
	if a.Severity != model.SeverityCritical || b.Severity != model.SeverityUnknown {
		t.Fatalf("max_lookups=1 must stop after one lookup: %v %v", a.Severity, b.Severity)
	}
	e.cfg.MaxLookups = 5
	if err := e.Enrich(context.Background(), []*model.Finding{b}); err != nil {
		t.Fatal(err)
	}
	if len(waits) == 0 || waits[len(waits)-1] < 6*time.Second {
		t.Fatalf("anonymous requests must be paced ~6.5s apart, waits = %v", waits)
	}
}

func TestErrorsMarkUnhealthyButKeepPartialResults(t *testing.T) {
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if r.URL.Query().Get("cveId") == "CVE-2024-0001" {
			_, _ = w.Write([]byte(recordV31))
			return
		}
		http.Error(w, "boom", http.StatusBadRequest)
	}))
	defer srv.Close()
	e := newEnricher(t, srv, nil, nil)
	a, b := finding("CVE-2024-0001"), finding("CVE-2024-0002")
	err := e.Enrich(context.Background(), []*model.Finding{a, b})
	if err == nil || a.Severity != model.SeverityCritical {
		t.Fatalf("err=%v a=%v: partial results kept and the failure reported", err, a.Severity)
	}
}
