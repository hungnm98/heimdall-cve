package endoflife

import (
	"context"
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

var clock = time.Date(2024, 12, 1, 12, 0, 0, 0, time.UTC)

type fakeEOL struct {
	mu    sync.Mutex
	calls map[string]int
}

func (f *fakeEOL) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	product, ok := strings.CutPrefix(r.URL.Path, "/api/")
	if !ok || !strings.HasSuffix(product, ".json") {
		http.NotFound(w, r)
		return
	}
	f.mu.Lock()
	f.calls[product]++
	f.mu.Unlock()
	b, err := os.ReadFile(filepath.Join("testdata", product))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write(b)
}

func (f *fakeEOL) count(product string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[product]
}

func newSource(t *testing.T, cache *httpx.Cache, opts plugin.Config) (*Source, *fakeEOL) {
	t.Helper()
	f := &fakeEOL{calls: map[string]int{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	if opts == nil {
		opts = plugin.Config{}
	}
	opts["base_url"] = srv.URL
	s, err := New(opts, plugin.Deps{HTTP: httpx.New(httpx.Options{}), Cache: cache})
	if err != nil {
		t.Fatal(err)
	}
	src := s.(*Source)
	src.now = func() time.Time { return clock }
	return src, f
}

func rt(name, v string) model.Runtime {
	return model.Runtime{Name: name, Version: v, Origin: "go.mod", Via: "go directive"}
}

func TestRegistered(t *testing.T) {
	if _, err := source.Runtime.Get(Name); err != nil {
		t.Fatal(err)
	}
}

func TestContract(t *testing.T) {
	s, _ := newSource(t, nil, nil)
	sourcetest.RunRuntime(t, s, []sourcetest.RuntimeCase{
		{Name: "go supported", Runtime: rt("go", "1.23.2"), Want: model.SupportSupported},
		{Name: "go eol-soon", Runtime: rt("go", "1.22.5"), Want: model.SupportEOLSoon},
		{Name: "go eol", Runtime: rt("go", "go1.21"), Want: model.SupportEOL},
		{Name: "go unknown cycle", Runtime: rt("go", "1.19"), Want: model.SupportUnknown},
		{Name: "node supported", Runtime: rt("node", "20.11.0"), Want: model.SupportSupported},
		{Name: "node major only", Runtime: rt("node", "v18"), Want: model.SupportSupported},
		{Name: "node eol", Runtime: rt("node", "16.20.0"), Want: model.SupportEOL},
		{Name: "ruby supported", Runtime: rt("ruby", "3.3.0"), Want: model.SupportSupported},
		{Name: "ruby eol date", Runtime: rt("ruby", "3.0.6"), Want: model.SupportEOL},
		{Name: "ruby eol bool", Runtime: rt("ruby", "2.7.8"), Want: model.SupportEOL},
		{Name: "unparseable", Runtime: rt("ruby", "latest"), Want: model.SupportUnknown},
	})
}

func TestEvaluateDetails(t *testing.T) {
	s, _ := newSource(t, nil, nil)
	ctx := context.Background()
	for _, c := range []struct {
		rt                          model.Runtime
		cycle, latestPatch, latestC string
		eol                         string
	}{
		{rt("go", "1.22.5"), "1.22", "1.22.10", "1.23", "2025-02-11"},
		{rt("go", "1.23"), "1.23", "1.23.4", "1.23", ""},
		{rt("node", ">=20.1"), "20", "20.18.1", "23", "2026-04-30"},
		{rt("ruby", "3.1.4"), "3.1", "3.1.6", "3.3", "2025-03-31"},
		{rt("ruby", "2.7.8"), "2.7", "2.7.8", "3.3", ""},
	} {
		st, err := s.Evaluate(ctx, c.rt)
		if err != nil {
			t.Fatal(err)
		}
		eol := ""
		if st.EOLDate != nil {
			eol = st.EOLDate.Format(time.DateOnly)
		}
		if st.Cycle != c.cycle || st.LatestPatch != c.latestPatch || st.LatestCycle != c.latestC || eol != c.eol || st.Source != Name {
			t.Errorf("%+v: got cycle=%s patch=%s latestCycle=%s eol=%s", c.rt, st.Cycle, st.LatestPatch, st.LatestCycle, eol)
		}
	}
}

func TestWarningDaysOption(t *testing.T) {
	s, _ := newSource(t, nil, plugin.Config{"eol_warning_days": 150})
	st, err := s.Evaluate(context.Background(), rt("ruby", "3.1.4")) // EOL in 120 days
	if err != nil || st.Status != model.SupportEOLSoon {
		t.Fatalf("status = %v, %v; want eol-soon", st, err)
	}
	s.now = func() time.Time { return time.Date(2025, 3, 31, 0, 0, 0, 0, time.UTC) } // EOL day
	if st, _ := s.Evaluate(context.Background(), rt("ruby", "3.1.4")); st.Status != model.SupportEOL {
		t.Fatalf("on EOL day status = %s; want eol", st.Status)
	}
}

func TestCache(t *testing.T) {
	cache, err := httpx.NewCache(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s, f := newSource(t, cache, nil)
	for _, v := range []string{"1.22.1", "1.23.0", "1.21.3"} {
		if _, err := s.Evaluate(context.Background(), rt("go", v)); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.count("go.json"); n != 1 {
		t.Errorf("go.json fetched %d times; want 1 (cached)", n)
	}
}

func TestErrors(t *testing.T) {
	s, _ := newSource(t, nil, nil)
	if s.Supports("python") {
		t.Error("python must not be supported")
	}
	if _, err := s.Evaluate(context.Background(), rt("python", "3.12")); err == nil {
		t.Error("unsupported runtime must fail")
	}
	products["missing"] = "missing" // no fixture: server returns 404
	defer delete(products, "missing")
	if _, err := s.Evaluate(context.Background(), rt("missing", "1.0")); err == nil {
		t.Error("HTTP failure must be returned")
	}
	for _, bad := range []plugin.Config{{"eol_warning_days": -1}, {"base_url": "::"}, {"unknown": true}} {
		if _, err := New(bad, plugin.Deps{HTTP: httpx.New(httpx.Options{})}); err == nil {
			t.Errorf("New(%v) accepted invalid config", bad)
		}
	}
}

func TestCandidateCycles(t *testing.T) {
	for in, want := range map[string]string{
		"1.22.5": "[1.22 1]", "go1.22": "[1.22 1]", "20": "[20]", "v20.11.0": "[20.11 20]",
		"^3.2.1": "[3.2 3]", "~> 3.1": "[3.1 3]", "1.22rc1": "[1.22 1]", "": "[]", "latest": "[]",
	} {
		if got := fmt.Sprint(candidateCycles(in)); got != want {
			t.Errorf("candidateCycles(%q) = %s; want %s", in, got, want)
		}
	}
}
