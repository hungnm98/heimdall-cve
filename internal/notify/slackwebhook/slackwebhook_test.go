package slackwebhook

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
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
	"github.com/hungnm98/heimdall-cve/internal/notify"
	"github.com/hungnm98/heimdall-cve/internal/notify/notifytest"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
)

var update = flag.Bool("update", false, "rewrite golden files")

const (
	hookPath = "/services/T0000/B0000/SuperSecretToken123"
	hookEnv  = "HEIMDALL_TEST_SLACK_WEBHOOK"
)

// fakeSlack records webhook posts and answers like Slack ("ok").
type fakeSlack struct {
	*httptest.Server
	mu     sync.Mutex
	bodies [][]byte
	status int
	reply  string
}

func newFakeSlack(t *testing.T) *fakeSlack {
	t.Helper()
	f := &fakeSlack{status: http.StatusOK, reply: "ok"}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Method != http.MethodPost || r.URL.Path != hookPath || r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		f.bodies = append(f.bodies, b)
		w.WriteHeader(f.status)
		_, _ = io.WriteString(w, f.reply)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeSlack) respond(status int, reply string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.reply = status, reply
}

func (f *fakeSlack) delivered() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.bodies)
}

func (f *fakeSlack) last() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bodies[len(f.bodies)-1]
}

func newNotifier(t *testing.T, url string, cfg plugin.Config, log *slog.Logger) notify.Notifier {
	t.Helper()
	t.Setenv(hookEnv, url)
	if cfg == nil {
		cfg = plugin.Config{}
	}
	cfg["webhook_env"] = hookEnv
	factory, err := notify.Registry.Get(Name)
	if err != nil {
		t.Fatal(err)
	}
	n, err := factory(cfg, plugin.Deps{
		HTTP:   httpx.New(httpx.Options{MaxRetries: 1, BaseBackoff: time.Millisecond, MaxBackoff: time.Millisecond}),
		Logger: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestContract(t *testing.T) {
	srv := newFakeSlack(t)
	n := newNotifier(t, srv.URL+hookPath, nil, nil)
	notifytest.Run(t, n, srv.delivered)
}

func TestGoldenPayloads(t *testing.T) {
	srv := newFakeSlack(t)
	n := newNotifier(t, srv.URL+hookPath, plugin.Config{
		"channel_label": "#sec-deps", "ui_base_url": "https://heimdall.example/",
	}, nil)
	for _, ev := range notifytest.Events() {
		t.Run(string(ev.Type), func(t *testing.T) {
			if err := n.Notify(context.Background(), ev); err != nil {
				t.Fatal(err)
			}
			body := srv.last()
			checkLimits(t, body)
			var pretty bytes.Buffer
			if err := json.Indent(&pretty, bytes.TrimSpace(body), "", "  "); err != nil {
				t.Fatal(err)
			}
			pretty.WriteByte('\n')
			golden(t, string(ev.Type)+".json", pretty.Bytes())
		})
	}
}

func TestAgentMessageLabelledUnverified(t *testing.T) {
	for _, ev := range notifytest.Events() {
		if ev.Type != model.EventAgentMessage {
			continue
		}
		f := notifytest.Events()[1].Findings[0] // Verified is false
		ev.Findings = []model.Finding{f}
		b, _ := json.Marshal(render(ev, Config{MaxFindings: 10}))
		if !strings.Contains(string(b), "AI agent — unverified") || !strings.Contains(string(b), "_unverified_") {
			t.Fatalf("agent message with unverified finding not labelled:\n%s", b)
		}
		f.Verified = true
		ev.Findings = []model.Finding{f}
		b, _ = json.Marshal(render(ev, Config{MaxFindings: 10}))
		if strings.Contains(string(b), "unverified") {
			t.Fatalf("verified agent finding labelled unverified:\n%s", b)
		}
	}
}

func manyFindings(n int) []model.Finding {
	base := notifytest.Events()[0].Findings[0]
	out := make([]model.Finding, n)
	for i := range out {
		f := base
		f.ID = fmt.Sprintf("f%03d", i)
		f.Package = model.NewPackage(model.EcosystemNPM, fmt.Sprintf("@scope/package-%03d-%s", i, strings.Repeat("x", 80)), "1.0.0")
		f.Summary = strings.Repeat("long summary ", 50)
		f.Severity = []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityLow}[i%3]
		out[i] = f
	}
	return out
}

func TestTruncation(t *testing.T) {
	srv := newFakeSlack(t)
	findings := manyFindings(200)
	runtimeF := model.Finding{ID: "rt", Kind: model.KindRuntime, Repo: "acme/api",
		Runtime: &model.RuntimeStatus{Runtime: model.Runtime{Name: "go", Version: "1.20"}, Status: model.SupportEOL}}

	t.Run("default max_findings", func(t *testing.T) {
		n := newNotifier(t, srv.URL+hookPath, nil, nil)
		for _, ev := range notifytest.Events() {
			ev.Findings = append(findings, runtimeF)
			if err := n.Notify(context.Background(), ev); err != nil {
				t.Fatal(err)
			}
			body := srv.last()
			checkLimits(t, body)
			if !strings.Contains(string(body), "…and 190 more") {
				t.Errorf("%s: missing \"…and 190 more\"", ev.Type)
			}
		}
	})
	t.Run("text limit", func(t *testing.T) {
		n := newNotifier(t, srv.URL+hookPath, plugin.Config{"max_findings": 1000, "ui_base_url": "https://heimdall.example"}, nil)
		ev := notifytest.Events()[1]
		ev.Findings = findings
		ev.Body = strings.Repeat("b", 5000)
		ev.Title = strings.Repeat("t", 500)
		for i := range 40 {
			ev.Links = append(ev.Links, fmt.Sprintf("https://example.com/%d", i))
		}
		if err := n.Notify(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
		body := srv.last()
		checkLimits(t, body)
		if !strings.Contains(string(body), "more") {
			t.Error("list was not truncated with \"…and N more\"")
		}
	})
}

// checkLimits enforces the Slack Block Kit limits on a payload.
func checkLimits(t *testing.T, body []byte) {
	t.Helper()
	var m struct {
		Text   string `json:"text"`
		Blocks []struct {
			Type     string `json:"type"`
			Text     *struct{ Text string }
			Fields   []struct{ Text string }
			Elements []struct {
				Text json.RawMessage
				URL  string
			}
		} `json:"blocks"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	if m.Text == "" || len(m.Blocks) == 0 || len(m.Blocks) > maxBlocks {
		t.Fatalf("text %q, %d blocks", m.Text, len(m.Blocks))
	}
	for i, b := range m.Blocks {
		if b.Text != nil {
			limit := maxText
			if b.Type == "header" {
				limit = maxHeader
			}
			if l := len(b.Text.Text); l == 0 || l > limit {
				t.Errorf("block %d (%s): text length %d", i, b.Type, l)
			}
		}
		if len(b.Fields) > maxFields {
			t.Errorf("block %d: %d fields", i, len(b.Fields))
		}
		for _, f := range b.Fields {
			if len(f.Text) > maxField {
				t.Errorf("block %d: field length %d", i, len(f.Text))
			}
		}
		if b.Type == "actions" && len(b.Elements) > maxButtons {
			t.Errorf("block %d: %d buttons", i, len(b.Elements))
		}
	}
}

func TestErrorsNeverLeakWebhook(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ev := notifytest.Events()[0]

	srv := newFakeSlack(t)
	srv.respond(http.StatusNotFound, "no_service "+hookPath)
	n := newNotifier(t, srv.URL+hookPath, nil, log)
	err := n.Notify(context.Background(), ev)
	assertRedacted(t, "HTTP 404", err, "404")

	srv.respond(http.StatusInternalServerError, "boom")
	err = n.Notify(context.Background(), ev)
	assertRedacted(t, "HTTP 500 after retries", err, "500")

	srv.respond(http.StatusOK, "ok")
	if err := n.Notify(context.Background(), ev); err != nil {
		t.Fatal(err)
	}

	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	n = newNotifier(t, closed.URL+hookPath, nil, log)
	err = n.Notify(context.Background(), ev)
	assertRedacted(t, "connection refused", err, "deliver")

	ctx, cancel := context.WithTimeout(context.Background(), -time.Second)
	defer cancel()
	err = n.Notify(ctx, ev)
	assertRedacted(t, "expired context", err, "deadline")

	if strings.Contains(logs.String(), "SuperSecretToken123") {
		t.Errorf("logs contain the webhook URL:\n%s", logs.String())
	}
}

func assertRedacted(t *testing.T, name string, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected an error", name)
	}
	if strings.Contains(err.Error(), "SuperSecretToken123") || strings.Contains(err.Error(), "/services/") {
		t.Errorf("%s: error leaks the webhook URL: %v", name, err)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("%s: error %q lacks %q", name, err, want)
	}
}

func TestConfigValidation(t *testing.T) {
	deps := plugin.Deps{HTTP: httpx.New(httpx.Options{})}
	for name, cfg := range map[string]plugin.Config{
		"no webhook":       {},
		"unknown key":      {"webhook_env": "X", "webhok": "typo"},
		"negative max":     {"webhook_env": "X", "max_findings": -1},
		"relative ui base": {"webhook_env": "X", "ui_base_url": "heimdall.internal"},
	} {
		if _, err := New(cfg, deps); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := New(plugin.Config{"webhook_ref": "slack-hook"}, deps); err != nil {
		t.Errorf("webhook_ref: %v", err)
	}
	if _, err := New(plugin.Config{"webhook_env": "X"}, plugin.Deps{}); err == nil {
		t.Error("missing HTTP client must fail")
	}
}

func TestMissingSecret(t *testing.T) {
	n, err := New(plugin.Config{"webhook_env": "HEIMDALL_TEST_UNSET_VAR"}, plugin.Deps{HTTP: httpx.New(httpx.Options{})})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(context.Background(), notifytest.Events()[0]); err == nil || !strings.Contains(err.Error(), "resolve webhook URL") {
		t.Fatalf("got %v", err)
	}
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read golden %s (run `go test -update` to create it): %v", p, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("payload differs from %s (run `go test -update` if intended)\n--- got ---\n%s", p, got)
	}
}
