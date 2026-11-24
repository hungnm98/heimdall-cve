package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/ecosystem"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
)

func writeConfig(t *testing.T, extra string) string {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "heimdall.yaml")
	body := "store: { type: memory }\ncache: { dir: " + dir + " }\nreport: { formats: [] }\n" + extra
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestWorkerNeedsSharedQueue(t *testing.T) {
	code, _, stderr := run("worker", "-c", writeConfig(t, "jobs: { type: inline }\n"))
	if code != ExitError || !strings.Contains(stderr, "asynq") {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
}

// The worker starts on asynq + a catalog store and stops cleanly when its
// ctx is canceled (what SIGINT/SIGTERM do).
func TestWorkerRunsAndStops(t *testing.T) {
	addr := os.Getenv("HEIMDALL_TEST_VALKEY_ADDR")
	if addr == "" {
		t.Skip("HEIMDALL_TEST_VALKEY_ADDR not set")
	}
	// No ecosystem plugin is compiled in yet; app.New needs one.
	ecosystem.Registry.Register("worker-test", func(plugin.Config, ecosystem.Options, plugin.Deps) (ecosystem.Ecosystem, error) {
		return nil, nil
	})
	cfg := writeConfig(t, "ecosystems: [worker-test]\njobs: { type: asynq, addr: \""+addr+"\", queue: heimdall-cli-test }\n")
	var out, errb syncBuffer
	root := NewRoot(&out, &errb)
	root.SetArgs([]string{"worker", "-c", cfg})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- root.ExecuteContext(ctx) }()
	time.Sleep(1500 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("worker: %v\n%s", err, errb.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("worker did not stop")
	}
	if logs := errb.String(); !strings.Contains(logs, "worker started") || !strings.Contains(logs, "worker stopped") {
		t.Fatalf("logs:\n%s", logs)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func masterKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestSecretsRotateKEK(t *testing.T) {
	cfg := writeConfig(t, "")
	t.Setenv("HEIMDALL_MASTER_KEY", "")
	t.Setenv("HEIMDALL_MASTER_KEY_OLD", "")
	if code, _, stderr := run("secrets", "rotate-kek", "-c", cfg); code != ExitError || !strings.Contains(stderr, "new master key") {
		t.Fatalf("missing key: code=%d stderr=%s", code, stderr)
	}
	newKey, oldKey := masterKey(t), masterKey(t)
	t.Setenv("HEIMDALL_MASTER_KEY", newKey)
	if code, _, stderr := run("secrets", "rotate-kek", "-c", cfg); code != ExitError || !strings.Contains(stderr, "HEIMDALL_MASTER_KEY_OLD") {
		t.Fatalf("missing old keys: code=%d stderr=%s", code, stderr)
	}
	t.Setenv("HEIMDALL_MASTER_KEY_OLD", oldKey+", ")
	code, out, stderr := run("secrets", "rotate-kek", "-c", cfg)
	if code != ExitOK || !strings.Contains(out, "re-wrapped 0 secret(s)") {
		t.Fatalf("code=%d out=%s stderr=%s", code, out, stderr)
	}
	if strings.Contains(out+stderr, newKey) || strings.Contains(out+stderr, oldKey) {
		t.Fatal("master keys must never be printed")
	}
}
