package kev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/httpx"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/source"
)

const catalog = `{"title":"CISA KEV","count":2,"vulnerabilities":[
 {"cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j2","dateAdded":"2021-12-10","knownRansomwareCampaignUse":"Known"},
 {"cveID":"CVE-2022-22965","vendorProject":"VMware","product":"Spring Framework","dateAdded":"2022-04-04"}]}`

func setup(t *testing.T, cfg plugin.Config) (*Enricher, *atomic.Int32, *atomic.Bool) {
	t.Helper()
	var calls atomic.Int32
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		if down.Load() {
			http.Error(w, "down", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(catalog))
	}))
	t.Cleanup(srv.Close)
	cache, err := httpx.NewCache(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		cfg = plugin.Config{}
	}
	cfg["url"] = srv.URL
	e, err := New(cfg, plugin.Deps{HTTP: httpx.New(httpx.Options{}), Cache: cache})
	if err != nil {
		t.Fatal(err)
	}
	return e.(*Enricher), &calls, &down
}

func TestRegistered(t *testing.T) {
	if _, err := source.Enrichers.Get(Name); err != nil {
		t.Fatal(err)
	}
}

func TestEnrich(t *testing.T) {
	e, calls, _ := setup(t, nil)
	log4j := &model.Finding{Kind: model.KindDependency, AdvisoryID: "GHSA-jfh8-c2jp-5v3q", Aliases: []string{"CVE-2021-44228"}}
	other := &model.Finding{Kind: model.KindDependency, AdvisoryID: "CVE-2024-0001"}
	runtime := &model.Finding{Kind: model.KindRuntime, AdvisoryID: "CVE-2022-22965"}
	ctx := context.Background()
	if err := e.Enrich(ctx, []*model.Finding{log4j, other, runtime}); err != nil {
		t.Fatal(err)
	}
	if !log4j.InKEV || other.InKEV || runtime.InKEV {
		t.Fatalf("InKEV: log4j=%v other=%v runtime=%v", log4j.InKEV, other.InKEV, runtime.InKEV)
	}
	// Cached: a second run does not download the catalog again.
	if err := e.Enrich(ctx, []*model.Finding{{Kind: model.KindDependency, AdvisoryID: "CVE-2022-22965"}}); err != nil || calls.Load() != 1 {
		t.Fatalf("err=%v downloads=%d, want 1", err, calls.Load())
	}
	// No CVE: no download at all.
	e2, calls2, _ := setup(t, nil)
	if err := e2.Enrich(ctx, []*model.Finding{{Kind: model.KindDependency, AdvisoryID: "GO-2026-0001"}}); err != nil || calls2.Load() != 0 {
		t.Fatalf("err=%v downloads=%d, want 0", err, calls2.Load())
	}
}

func TestStaleCatalogOnFailure(t *testing.T) {
	e, _, down := setup(t, plugin.Config{"cache_ttl": "1ns"})
	ctx := context.Background()
	if err := e.Enrich(ctx, []*model.Finding{{Kind: model.KindDependency, AdvisoryID: "CVE-2021-44228"}}); err != nil {
		t.Fatal(err)
	}
	down.Store(true)
	f := &model.Finding{Kind: model.KindDependency, AdvisoryID: "CVE-2021-44228"}
	err := e.Enrich(ctx, []*model.Finding{f})
	if err == nil || !f.InKEV {
		t.Fatalf("a failed refresh must use the stale catalog and report it: err=%v InKEV=%v", err, f.InKEV)
	}
}
