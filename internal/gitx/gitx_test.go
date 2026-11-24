package gitx

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	r := Runner{}
	ctx := context.Background()
	if _, err := r.Run(ctx, dir, nil, "init", "-q", "-b", "main"); err != nil {
		t.Fatal(err)
	}
	out, err := r.Run(ctx, dir, nil, "symbolic-ref", "--short", "HEAD")
	if err != nil || strings.TrimSpace(string(out)) != "main" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if _, err := r.Run(ctx, dir, nil, "no-such-subcommand"); err == nil || !strings.Contains(err.Error(), "no-such-subcommand") {
		t.Fatalf("want error with stderr, got %v", err)
	}
}

func TestSSHCommand(t *testing.T) {
	got := SSHCommand(SSH{KeyFile: "/k/id's", KnownHostsFile: "/k/known"})
	for _, want := range []string{"BatchMode=yes", "StrictHostKeyChecking=yes", `-i '/k/id'\''s'`, "UserKnownHostsFile='/k/known'"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q missing %q", got, want)
		}
	}
}
