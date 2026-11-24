package epss

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

var known = map[string]string{
	"CVE-2021-44228": `{"cve":"CVE-2021-44228","epss":"0.944310000","percentile":"0.999950000","date":"2026-11-24"}`,
	"CVE-2024-0001":  `{"cve":"CVE-2024-0001","epss":"0.000430000","percentile":"0.110000000","date":"2026-11-24"}`,
}

func TestRegistered(t *testing.T) {
	if _, err := source.Enrichers.Get(Name); err != nil {
		t.Fatal(err)
	}
}

func TestEnrich(t *testing.T) {
	var mu sync.Mutex
	var queried []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		ids := strings.Split(r.URL.Query().Get("cve"), ",")
		queried = append(queried, ids...)
		var rows []string
		for _, id := range ids {
			if row, ok := known[id]; ok {
				rows = append(rows, row)
			}
		}
		_, _ = w.Write([]byte(`{"status":"OK","data":[` + strings.Join(rows, ",") + `]}`))
	}))
	defer srv.Close()
	cache, err := httpx.NewCache(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(plugin.Config{"base_url": srv.URL}, plugin.Deps{HTTP: httpx.New(httpx.Options{}), Cache: cache})
	if err != nil {
		t.Fatal(err)
	}
	log4j := &model.Finding{Kind: model.KindDependency, AdvisoryID: "GHSA-jfh8-c2jp-5v3q", Aliases: []string{"CVE-2024-0001", "CVE-2021-44228"}}
	unknown := &model.Finding{Kind: model.KindDependency, AdvisoryID: "CVE-2099-0001"}
	ctx := context.Background()
	if err := e.Enrich(ctx, []*model.Finding{log4j, unknown}); err != nil {
		t.Fatal(err)
	}
	if log4j.EPSS != 0.94431 || log4j.EPSSPercentile != 0.99995 || unknown.EPSS != 0 {
		t.Fatalf("highest alias EPSS wins: log4j=%v/%v unknown=%v", log4j.EPSS, log4j.EPSSPercentile, unknown.EPSS)
	}
	if len(queried) != 3 {
		t.Fatalf("queried %v, want 3 CVEs in one batch", queried)
	}
	// Hits and misses are cached.
	again := &model.Finding{Kind: model.KindDependency, AdvisoryID: "CVE-2021-44228", Aliases: []string{"CVE-2099-0001"}}
	if err := e.Enrich(ctx, []*model.Finding{again}); err != nil || again.EPSS == 0 || len(queried) != 3 {
		t.Fatalf("err=%v epss=%v queried=%v", err, again.EPSS, queried)
	}
}
