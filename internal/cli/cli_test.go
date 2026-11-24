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
	// The github/token plugins are compiled in, so they must not be reported
	// missing; any plugin still missing makes validation fail with exit code 2.
	code, _, stderr := run("config", "validate", "-c", cfg)
	if strings.Contains(stderr, `auth "token"`) || strings.Contains(stderr, `vcs "github"`) ||
		(code != ExitOK && (code != ExitError || !strings.Contains(stderr, "plugin not registered"))) {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	if code, _, stderr := run("config", "validate", "-c", filepath.Join(dir, "missing.yaml")); code != ExitError || stderr == "" {
		t.Fatalf("missing file: code=%d stderr=%s", code, stderr)
	}
}
