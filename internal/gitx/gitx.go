// Package gitx wraps the git binary. Plugins that need git (SSH mode, code
// checkout) use it instead of calling os/exec themselves.
package gitx

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// SSH configures how git authenticates over SSH.
type SSH struct {
	KeyFile        string // empty = use ssh-agent / default keys
	KnownHostsFile string // empty = ssh default
}

// Runner runs git commands.
type Runner struct {
	Bin string // default "git"
}

// Run executes git args in dir and returns stdout. stderr is included in the
// error. The environment is minimal: no credentials leak in from the parent
// beyond what ssh needs (HOME, PATH, SSH_AUTH_SOCK).
func (r Runner) Run(ctx context.Context, dir string, ssh *SSH, args ...string) ([]byte, error) {
	bin := r.Bin
	if bin == "" {
		bin = "git"
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Env = env(ssh)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func env(ssh *SSH) []string {
	out := []string{"GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1"}
	for _, k := range []string{"HOME", "PATH", "SSH_AUTH_SOCK", "TMPDIR", "SYSTEMROOT"} {
		if v, ok := os.LookupEnv(k); ok {
			out = append(out, k+"="+v)
		}
	}
	if ssh != nil {
		out = append(out, "GIT_SSH_COMMAND="+SSHCommand(*ssh))
	}
	return out
}

// SSHCommand builds a non-interactive ssh command line for GIT_SSH_COMMAND.
func SSHCommand(s SSH) string {
	parts := []string{"ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes"}
	if s.KeyFile != "" {
		parts = append(parts, "-i", shellQuote(s.KeyFile), "-o", "IdentitiesOnly=yes")
	}
	if s.KnownHostsFile != "" {
		parts = append(parts, "-o", "UserKnownHostsFile="+shellQuote(s.KnownHostsFile))
	}
	return strings.Join(parts, " ")
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
