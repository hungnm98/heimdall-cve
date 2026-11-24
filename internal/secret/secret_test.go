package secret

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestResolve(t *testing.T) {
	t.Setenv("HEIMDALL_TEST_SECRET", " from-env \n")
	if v, err := Resolve("HEIMDALL_TEST_SECRET", ""); err != nil || v != "from-env" {
		t.Fatalf("env: %q %v", v, err)
	}
	f := filepath.Join(t.TempDir(), "s")
	if err := os.WriteFile(f, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if v, err := Resolve("HEIMDALL_UNSET_VAR", f); err != nil || v != "from-file" {
		t.Fatalf("file: %q %v", v, err)
	}
	if _, err := Resolve("HEIMDALL_UNSET_VAR", ""); !errors.Is(err, ErrMissing) {
		t.Fatalf("missing: %v", err)
	}
}

func TestRedact(t *testing.T) {
	if Redact("ghp_abcdef1234") != "****1234" || Redact("abc") != "****" {
		t.Fatal("Redact")
	}
}
