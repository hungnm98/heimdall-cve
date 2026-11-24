package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/auth"
	"github.com/hungnm98/heimdall-cve/internal/config"
	"github.com/hungnm98/heimdall-cve/internal/ecosystem"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/notify"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/registry"
	"github.com/hungnm98/heimdall-cve/internal/report"
	"github.com/hungnm98/heimdall-cve/internal/runtime"
	"github.com/hungnm98/heimdall-cve/internal/source"
	"github.com/hungnm98/heimdall-cve/internal/vcs"
	"github.com/hungnm98/heimdall-cve/internal/version"
)

// Fakes registered under "test-*" names so they never clash with real plugins.
type fakeCreds struct{ method string }

func (c fakeCreds) Method() string { return c.method }

type fakeProvider struct {
	vcs.Provider
	creds vcs.Credentials
	opts  plugin.Config
}

func (fakeProvider) Name() string { return "test-vcs" }

type fakeEco struct{}

func (fakeEco) Name() model.Ecosystem        { return "test-eco" }
func (fakeEco) Match(string) bool            { return false }
func (fakeEco) Versions() version.Comparator { return version.Go{} }
func (fakeEco) Parse(context.Context, model.FileSet) ([]*model.DependencyGraph, error) {
	return nil, nil
}

type fakeDetector struct{ rt string }

func (d fakeDetector) Name() string    { return "test-detector-" + d.rt }
func (d fakeDetector) Runtime() string { return d.rt }
func (fakeDetector) Match(string) bool { return false }
func (fakeDetector) Detect(context.Context, model.FileSet) ([]model.Runtime, error) {
	return nil, nil
}

type fakeVuln struct{ opts plugin.Config }

func (fakeVuln) Name() string                  { return "test-vuln" }
func (fakeVuln) Supports(model.Ecosystem) bool { return true }
func (fakeVuln) Query(context.Context, []model.Package) ([]model.Advisory, error) {
	return nil, nil
}

type fakeRuntimeSource struct{}

func (fakeRuntimeSource) Name() string         { return "test-vuln" }
func (fakeRuntimeSource) Supports(string) bool { return true }
func (fakeRuntimeSource) Evaluate(context.Context, model.Runtime) (*model.RuntimeStatus, error) {
	return nil, nil
}

type fakeNotifier struct{}

func (fakeNotifier) Name() string                                          { return "test-notify" }
func (fakeNotifier) Notify(context.Context, model.NotificationEvent) error { return nil }

type fakeReporter struct{}

func (fakeReporter) Format() string                        { return "test-fmt" }
func (fakeReporter) FileExtension() string                 { return ".txt" }
func (fakeReporter) Render(io.Writer, *model.Report) error { return nil }

func init() {
	auth.Registry.Register("test-token", func(plugin.Config, plugin.Deps) (auth.Credentials, error) {
		return fakeCreds{"test-token"}, nil
	})
	auth.Registry.Register("test-ssh", func(plugin.Config, plugin.Deps) (auth.Credentials, error) {
		return fakeCreds{"test-ssh"}, nil
	})
	vcs.Registry.Register("test-vcs", func(opts plugin.Config, c vcs.Credentials, _ plugin.Deps) (vcs.Provider, error) {
		return fakeProvider{creds: c, opts: opts}, nil
	})
	ecosystem.Registry.Register("test-eco", func(plugin.Config, ecosystem.Options, plugin.Deps) (ecosystem.Ecosystem, error) {
		return fakeEco{}, nil
	})
	runtime.Registry.Register("test-detector-go", func(plugin.Config, plugin.Deps) (runtime.Detector, error) {
		return fakeDetector{"go"}, nil
	})
	runtime.Registry.Register("test-detector-node", func(plugin.Config, plugin.Deps) (runtime.Detector, error) {
		return fakeDetector{"node"}, nil
	})
	// test-vuln registers in two kinds, like osv (vulns + stdlib runtime).
	source.Vuln.Register("test-vuln", func(opts plugin.Config, _ plugin.Deps) (source.VulnSource, error) {
		return fakeVuln{opts}, nil
	})
	source.Runtime.Register("test-vuln", func(plugin.Config, plugin.Deps) (source.RuntimeSource, error) {
		return fakeRuntimeSource{}, nil
	})
	notify.Registry.Register("test-notify", func(plugin.Config, plugin.Deps) (notify.Notifier, error) {
		return fakeNotifier{}, nil
	})
	report.Registry.Register("test-fmt", func(plugin.Config, plugin.Deps) (report.Reporter, error) {
		return fakeReporter{}, nil
	})
	runtimeOf["test-eco"] = "go"
}

func baseConfig(t *testing.T) *config.Config {
	off := false
	return &config.Config{
		AuthProfiles: map[string]config.Plugin{
			"pat": {Type: "test-token"},
			"key": {Type: "test-ssh"},
		},
		Targets: []config.Target{
			{Kind: "org", Provider: "test-vcs", Name: "acme", Auth: "pat"},
			{Kind: "user", Provider: "test-vcs", Name: "dev", Auth: "pat"}, // shares provider with target 0
			{Kind: "repo", Provider: "test-vcs", URL: "git@ghe.example.com:acme/x.git", Auth: "key", ListAuth: "pat", BaseURL: "https://ghe.example.com/api/v3"},
		},
		Ecosystems: []string{"test-eco"},
		Sources: map[string]config.Plugin{
			"test-vuln": {Options: plugin.Config{"k": "v"}},
			"disabled":  {Type: "does-not-exist", Enabled: &off},
		},
		Notify:      map[string]config.Plugin{"sec": {Type: "test-notify"}},
		Report:      config.ReportConfig{Formats: []string{"test-fmt"}},
		Store:       config.Plugin{Type: "memory"},
		Cache:       config.CacheConfig{Dir: t.TempDir(), TTL: time.Hour},
		Concurrency: config.Concurrency{Repos: 1, HTTPPerHost: 1},
	}
}

func TestNewWiresPlugins(t *testing.T) {
	a, err := New(baseConfig(t), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	if len(a.providers) != 2 {
		t.Fatalf("providers = %d, want 2 (targets 0 and 1 share one)", len(a.providers))
	}
	p, err := a.Provider(a.Targets[2])
	if err != nil {
		t.Fatal(err)
	}
	fp := p.(fakeProvider)
	if fp.creds.Read.Method() != "test-ssh" || fp.creds.List.Method() != "test-token" || fp.opts["base_url"] != "https://ghe.example.com/api/v3" {
		t.Fatalf("repo target provider wired wrong: %+v", fp)
	}
	// Real detectors blank-imported in plugins.go register too, so only check
	// that every built detector is for the configured runtime.
	if len(a.Ecosystems) != 1 || len(a.Detectors) == 0 {
		t.Fatalf("ecosystems=%d detectors=%v; want 1 eco and the go detectors", len(a.Ecosystems), a.Detectors)
	}
	for _, d := range a.Detectors {
		if d.Runtime() != "go" {
			t.Fatalf("detector %s for runtime %s must not be built", d.Name(), d.Runtime())
		}
	}
	if len(a.VulnSources) != 1 || len(a.RuntimeSources) != 1 || a.VulnSources[0].(fakeVuln).opts["k"] != "v" {
		t.Fatalf("a source registered in two kinds must be built in both with its options")
	}
	if len(a.Notifiers) != 1 || len(a.Reporters) != 1 || a.Store == nil {
		t.Fatal("notifier, reporter and store must be built")
	}
}

func TestNewReportsAllMissingPlugins(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Store.Type = "nope-store"
	cfg.Sources["ghost"] = config.Plugin{}
	cfg.Report.Formats = []string{"nope-fmt"}
	_, err := New(cfg, slog.New(slog.DiscardHandler))
	if !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	for _, want := range []string{"nope-store", "ghost", "nope-fmt"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error must mention %q:\n%v", want, err)
		}
	}
}
