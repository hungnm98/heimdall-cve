package cli

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/app"
	"github.com/hungnm98/heimdall-cve/internal/config"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/store"
	"github.com/hungnm98/heimdall-cve/internal/store/memstore"
)

func TestServe(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	t.Setenv("HEIMDALL_TEST_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
	cfg := &config.Config{
		AuthProfiles: map[string]config.Plugin{"pat": {Type: "token", Options: plugin.Config{"token_env": "GITHUB_TOKEN"}}},
		Targets:      []config.Target{{Kind: "org", Name: "acme", Auth: "pat"}},
		Server:       config.Server{Listen: "127.0.0.1:0"},
		Jobs:         config.Plugin{Type: "inline"},
		Secrets:      config.SecretsConfig{MasterKeyEnv: "HEIMDALL_TEST_MASTER_KEY"},
	}
	a := &app.App{Config: cfg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Store: memstore.New()}
	ctx, cancel := context.WithCancel(context.Background())
	addrc := make(chan net.Addr, 1)
	errc := make(chan error, 1)
	go func() { errc <- serve(ctx, a, func(addr net.Addr) { addrc <- addr }) }()
	var base string
	select {
	case addr := <-addrc:
		base = "http://" + addr.String()
	case err := <-errc:
		t.Fatal(err)
	}

	get := func(path string) (int, string) {
		resp, err := http.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, _ := get("/healthz"); code != 200 {
		t.Fatal("healthz", code)
	}
	if code, _ := get("/readyz"); code != 200 {
		t.Fatal("readyz", code)
	}
	code, body := get("/api/v1/meta")
	var meta map[string]any
	_ = json.Unmarshal([]byte(body), &meta)
	if code != 200 || meta["secrets_enabled"] != true || meta["jobs_backend"] != "inline" {
		t.Fatal(code, body)
	}
	// Config targets are synced read-only.
	if code, body := get("/api/v1/targets"); code != 200 || !strings.Contains(body, `"origin":"config"`) {
		t.Fatal(code, body)
	}
	if code, body := get("/some/spa/route"); code != 200 || !strings.Contains(body, "Heimdall") {
		t.Fatal(code, body)
	}

	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not shut down")
	}
}

func TestServeNeedsCatalog(t *testing.T) {
	a := &app.App{Config: &config.Config{Store: config.Plugin{Type: "nocat"}}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Store: noCatalog{memstore.New()}}
	if err := serve(context.Background(), a, nil); err == nil || !strings.Contains(err.Error(), "catalog") {
		t.Fatal(err)
	}
}

type noCatalog struct{ store.Store } // hides memstore's Catalog methods
