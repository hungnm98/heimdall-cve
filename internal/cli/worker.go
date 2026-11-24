package cli

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/hungnm98/heimdall-cve/internal/app"
	"github.com/hungnm98/heimdall-cve/internal/config"
	"github.com/hungnm98/heimdall-cve/internal/secret"
	"github.com/hungnm98/heimdall-cve/internal/service"
	"github.com/spf13/cobra"
)

func newWorkerCmd(g *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "worker",
		Short: "Run scan jobs from the shared queue, plus the scheduler (scale horizontally)",
		Long: "Processes scan jobs from the configured queue backend (jobs.type: asynq) and runs the\n" +
			"scheduler (one replica works per tick). Stops gracefully on SIGINT/SIGTERM: running jobs\n" +
			"are interrupted and go back to the queue.",
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
			if cfg.Jobs.Type == "" || cfg.Jobs.Type == "inline" {
				return errors.New("worker needs a shared queue: set jobs.type to asynq (inline jobs only live inside one process)")
			}
			a, err := app.New(cfg, logger)
			if err != nil {
				return err
			}
			defer a.Close()
			rt, err := a.NewWebRuntime(cmd.Context())
			if err != nil {
				return err
			}
			backend, deps := rt.Jobs, rt.Deps
			defer backend.Close()

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			logger.Info("worker started", "jobs", backend.Name(), "store", cfg.Store.Type)
			var wg sync.WaitGroup
			errs := make([]error, 2)
			wg.Add(2)
			go func() {
				defer wg.Done()
				errs[0] = backend.Run(ctx, service.NewJobHandler(deps))
				stop() // a dead worker pool must not leave the scheduler running alone
			}()
			go func() {
				defer wg.Done()
				errs[1] = service.NewScheduler(deps).Run(ctx)
				stop()
			}()
			wg.Wait()
			logger.Info("worker stopped")
			return errors.Join(errs...)
		},
	}
}

// loadKeyRing loads the master key from secrets.master_key_env/_file; nil
// when none is configured (secrets entered in the UI cannot be resolved then).
func loadKeyRing(cfg *config.Config, logger *slog.Logger) (*secret.KeyRing, error) {
	key, err := secret.Resolve(cfg.Secrets.MasterKeyEnv, cfg.Secrets.MasterKeyFile)
	if errors.Is(err, secret.ErrMissing) {
		logger.Warn("no master key: secrets stored in the web app cannot be used")
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("master key: %w", err)
	}
	return secret.NewKeyRing(key)
}
