// Package cli defines the heimdall cobra commands. Each command lives in its
// own file and is added in NewRoot.
package cli

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

// Exit codes.
const (
	ExitOK       = 0
	ExitFindings = 1 // findings at or above --fail-on
	ExitError    = 2 // runtime or config error
)

// ExitCodeError carries a specific exit code out of a command.
type ExitCodeError struct {
	Code int
	Err  error
}

func (e *ExitCodeError) Error() string { return e.Err.Error() }
func (e *ExitCodeError) Unwrap() error { return e.Err }

// Build info, set with -ldflags "-X github.com/hungnm98/heimdall-cve/internal/cli.Version=..."
var (
	Version = "dev"
	Commit  = "none"
)

type globalFlags struct {
	configFile string
	logFormat  string
	logLevel   string
}

// NewRoot builds the command tree.
func NewRoot(stdout, stderr io.Writer) *cobra.Command {
	g := &globalFlags{}
	root := &cobra.Command{
		Use:           "heimdall",
		Short:         "Watch every repo for vulnerable dependencies and EOL runtimes",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	pf := root.PersistentFlags()
	pf.StringVarP(&g.configFile, "config", "c", os.Getenv("HEIMDALL_CONFIG"), "config file (.yaml or .json); default ./heimdall.yaml (env HEIMDALL_CONFIG)")
	pf.StringVar(&g.logFormat, "log-format", "text", "log format: text | json")
	pf.StringVar(&g.logLevel, "log-level", "info", "log level: debug | info | warn | error")

	root.AddCommand(
		newVersionCmd(),
		newConfigCmd(g),
		newDBCmd(g),
		newPluginsCmd(),
	)
	return root
}

// Execute runs the CLI and returns the process exit code.
func Execute(args []string, stdout, stderr io.Writer) int {
	root := NewRoot(stdout, stderr)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		var ec *ExitCodeError
		if errors.As(err, &ec) {
			return ec.Code
		}
		return ExitError
	}
	return ExitOK
}

func (g *globalFlags) logger(w io.Writer) (*slog.Logger, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(g.logLevel)); err != nil {
		return nil, fmt.Errorf("--log-level: %w", err)
	}
	opts := &slog.HandlerOptions{Level: level}
	switch g.logFormat {
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	}
	return nil, fmt.Errorf("--log-format must be text or json, got %q", g.logFormat)
}
