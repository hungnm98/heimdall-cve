package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Execute(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestVersionAndPlugins(t *testing.T) {
	if code, out, _ := run("version"); code != ExitOK || !strings.Contains(out, "heimdall dev") {
		t.Fatalf("version: %d %q", code, out)
	}
	code, out, _ := run("plugins")
	if code != ExitOK || !strings.Contains(out, "store") || !strings.Contains(out, "memory") {
		t.Fatalf("plugins: %d %q", code, out)
	}
}

func TestConfigValidate(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "heimdall.yaml")
	body := "auth_profiles: { pat: { type: token, token_env: GITHUB_TOKEN } }\n" +
		"targets: [ { kind: org, name: acme, auth: pat } ]\n" +
		"store: { type: memory }\ncache: { dir: " + dir + " }\nreport: { formats: [] }\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// Every plugin this config needs is compiled in: validation succeeds.
	code, out, stderr := run("config", "validate", "-c", cfg)
	if code != ExitOK || !strings.Contains(out, "config OK") {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, out, stderr)
	}
	// An unknown plugin type is reported with exit code 2.
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte(strings.Replace(body, "type: token", "type: nope", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := run("config", "validate", "-c", bad); code != ExitError || !strings.Contains(stderr, `auth "nope"`) {
		t.Fatalf("unknown plugin: code=%d stderr=%s", code, stderr)
	}
	if code, _, stderr := run("config", "validate", "-c", filepath.Join(dir, "missing.yaml")); code != ExitError || stderr == "" {
		t.Fatalf("missing file: code=%d stderr=%s", code, stderr)
	}
}
