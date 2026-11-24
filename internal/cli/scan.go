package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"

	"github.com/hungnm98/heimdall-cve/internal/app"
	"github.com/hungnm98/heimdall-cve/internal/config"
	"github.com/hungnm98/heimdall-cve/internal/core"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
	"github.com/spf13/cobra"
)

func newScanCmd(g *globalFlags) *cobra.Command {
	var repo, failOn, out string
	var targets []string
	var quiet bool
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan the configured targets now, in this process",
		Long: "Scans the targets of the config file (default branch or the configured branch), records\n" +
			"the run in the store, writes reports, sends notifications for what changed, and exits 1\n" +
			"when an open finding is at least --fail-on severe (2 on errors).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(g.configFile)
			if err != nil {
				return err
			}
			logger, err := g.logger(cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			if failOn == "" {
				failOn = cfg.Policy.FailOn
			}
			if failOn != "" && model.ParseSeverity(failOn) == model.SeverityUnknown {
				return fmt.Errorf("--fail-on must be CRITICAL, HIGH, MEDIUM or LOW, got %q", failOn)
			}
			if out != "" {
				cfg.Report.Dir = out
			}
			a, err := app.New(cfg, logger)
			if err != nil {
				return err
			}
			defer a.Close()
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			if err := a.Store.Migrate(ctx); err != nil {
				return fmt.Errorf("store: %w", err)
			}
			sel, err := selectTargets(a.Targets, targets)
			if err != nil {
				return err
			}
			cat, _ := a.Store.(store.Catalog)
			p := a.Pipeline(cat, a.ConfigProviderFor)
			prog := progressPrinter(cmd.ErrOrStderr(), quiet)
			run, err := p.Scan(ctx, core.ScanRequest{Targets: sel, Repo: repo, Trigger: model.TriggerCLI}, prog)
			if err != nil {
				return err
			}
			open, err := openFindings(ctx, a.Store, run.ReposScanned)
			if err != nil {
				return err
			}
			printSummary(cmd.OutOrStdout(), run, open, cfg.Report.Dir, a)
			if failOn != "" {
				min := model.ParseSeverity(failOn)
				n := 0
				for _, f := range open {
					if f.Severity.AtLeast(min) {
						n++
					}
				}
				if n > 0 {
					return &ExitCodeError{Code: ExitFindings, Err: fmt.Errorf("%d open findings at or above %s", n, min)}
				}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&repo, "repo", "", "only scan this owner/name")
	f.StringSliceVar(&targets, "target", nil, "only these targets, by label (org:acme, user:bob, repo:acme/api); repeatable")
	f.StringVar(&failOn, "fail-on", "", "exit 1 when an open finding is at least this severe (default policy.fail_on)")
	f.StringVar(&out, "out", "", "report directory (default report.dir)")
	f.BoolVarP(&quiet, "quiet", "q", false, "only print warnings and errors while scanning")
	return cmd
}

func newReposCmd(g *globalFlags) *cobra.Command {
	var targets []string
	cmd := &cobra.Command{
		Use:   "repos",
		Short: "List the repos the configured targets resolve to (checks credentials and filters)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(g.configFile)
			if err != nil {
				return err
			}
			logger, err := g.logger(cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			a, err := app.New(cfg, logger)
			if err != nil {
				return err
			}
			defer a.Close()
			sel, err := selectTargets(a.Targets, targets)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "TARGET\tREPO\tREF\tFLAGS")
			var errs []error
			for _, t := range sel {
				p, err := a.Provider(t)
				if err != nil {
					errs = append(errs, fmt.Errorf("%s: %w", t, err))
					continue
				}
				repos, err := p.ListRepos(cmd.Context(), t)
				if err != nil {
					errs = append(errs, fmt.Errorf("%s: %w", t, err))
					continue
				}
				for _, r := range repos {
					var flags []string
					if r.Private {
						flags = append(flags, "private")
					}
					if r.Archived {
						flags = append(flags, "archived")
					}
					if r.Fork {
						flags = append(flags, "fork")
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", t, r.FullName(), r.Ref, strings.Join(flags, ","))
				}
			}
			w.Flush()
			return errors.Join(errs...)
		},
	}
	cmd.Flags().StringSliceVar(&targets, "target", nil, "only these targets, by label; repeatable")
	return cmd
}

func selectTargets(all []model.Target, labels []string) ([]model.Target, error) {
	if len(labels) == 0 {
		if len(all) == 0 {
			return nil, errors.New("no targets in the config file")
		}
		return all, nil
	}
	var out []model.Target
	for _, l := range labels {
		found := false
		for _, t := range all {
			if t.String() == l {
				out, found = append(out, t), true
			}
		}
		if !found {
			return nil, fmt.Errorf("no target %q in the config file", l)
		}
	}
	return out, nil
}

func progressPrinter(w io.Writer, quiet bool) core.Progress {
	var mu sync.Mutex
	return core.ProgressFunc(func(level, repo, msg string) {
		if quiet && level == "info" {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if repo != "" {
			msg = repo + ": " + msg
		}
		fmt.Fprintf(w, "%-5s %s\n", level, msg)
	})
}

func openFindings(ctx context.Context, s store.Store, repos []string) ([]model.Finding, error) {
	var out []model.Finding
	for _, r := range repos {
		fs, err := s.ListFindings(ctx, store.FindingFilter{Repo: r, Status: model.StatusOpen})
		if err != nil {
			return nil, err
		}
		out = append(out, fs...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity.Rank() > out[j].Severity.Rank() })
	return out, nil
}

func printSummary(w io.Writer, run *model.ScanRun, open []model.Finding, reportDir string, a *app.App) {
	fmt.Fprintf(w, "\nRun #%d %s: %d repos scanned, %d failed, %d new, %d fixed\n",
		run.ID, run.Status, len(run.ReposScanned), len(run.ReposFailed), run.Stats.New, run.Stats.Fixed)
	counts := map[model.Severity]int{}
	for _, f := range open {
		counts[f.Severity]++
	}
	fmt.Fprintf(w, "Open: %d CRITICAL, %d HIGH, %d MEDIUM, %d LOW, %d UNKNOWN\n",
		counts[model.SeverityCritical], counts[model.SeverityHigh], counts[model.SeverityMedium],
		counts[model.SeverityLow], counts[model.SeverityUnknown])
	for _, h := range run.Sources {
		if !h.Healthy {
			fmt.Fprintf(w, "Source %s unhealthy: %s\n", h.Name, h.Error)
		}
	}
	if len(open) > 0 {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "\nSEVERITY\tREPO\tPACKAGE\tCURRENT\tFIX\tBUMP\tADVISORY")
		for i, f := range open {
			if i == 20 {
				fmt.Fprintf(tw, "…\t%d more\t\t\t\t\t\n", len(open)-20)
				break
			}
			name, cur := f.Package.Name, f.Package.Version
			if f.Kind == model.KindRuntime && f.Runtime != nil {
				name, cur = f.Runtime.Runtime.Name+" (runtime)", f.Runtime.Runtime.Version
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", f.Severity, f.Repo, name, cur, f.RecommendedVersion, f.Bump, f.AdvisoryID)
		}
		tw.Flush()
	}
	if reportDir != "" && len(a.Reporters) > 0 {
		fmt.Fprintf(w, "\nReports: %s/run-%d.*\n", strings.TrimSuffix(reportDir, "/"), run.ID)
	}
}
