package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/api"
	"github.com/hungnm98/heimdall-cve/internal/app"
	"github.com/hungnm98/heimdall-cve/internal/auth"
	"github.com/hungnm98/heimdall-cve/internal/config"
	"github.com/hungnm98/heimdall-cve/internal/service"
	"github.com/hungnm98/heimdall-cve/internal/vcs"
	"github.com/hungnm98/heimdall-cve/internal/webui"
	"github.com/spf13/cobra"
)

func newServeCmd(g *globalFlags) *cobra.Command {
	var listen string
	var apiOnly bool
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the web UI and REST API",
		Long: "Serve the embedded web UI at / and the REST API at /api/v1.\n" +
			"There is no login: keep the default loopback address or put an SSO proxy in front.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(g.configFile)
			if err != nil {
				return err
			}
			if listen != "" {
				cfg.Server.Listen = listen
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
			return serveWith(cmd.Context(), a, nil, !apiOnly)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "", "listen address (default server.listen, 127.0.0.1:8080)")
	cmd.Flags().BoolVar(&apiOnly, "api-only", false, "serve the UI and API only; scan jobs are run by `heimdall worker` processes")
	return cmd
}

// serve runs the HTTP server until ctx is canceled or SIGINT/SIGTERM.
// onListen, if set, receives the bound address (tests listen on port 0).
func serve(ctx context.Context, a *app.App, onListen func(net.Addr)) error {
	return serveWith(ctx, a, onListen, true)
}

// serveWith runs the HTTP server and, when workers is true, the job worker
// pool and the scheduler in the same process (required for jobs.type inline).
func serveWith(ctx context.Context, a *app.App, onListen func(net.Addr), workers bool) error {
	cfg, logger := a.Config, a.Logger
	rt, err := a.NewWebRuntime(ctx)
	if err != nil {
		return err
	}
	backend, deps := rt.Jobs, rt.Deps
	defer backend.Close()
	keys := deps.Keys
	svcs := service.New(deps)

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	streamsDone := make(chan struct{})
	handler := api.NewHandler(svcs, api.Options{
		TrustedUserHeader: cfg.Server.TrustedUserHeader,
		Logger:            logger,
		Version:           Version,
		JobsBackend:       backend.Name(),
		Providers:         vcs.Registry.Names(),
		AuthTypes:         auth.Registry.Names(),
		Fallback:          webui.Handler(),
		Done:              streamsDone,
	})
	srv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	srv.RegisterOnShutdown(func() { close(streamsDone) })

	ln, err := net.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		return err
	}
	if !isLoopback(ln.Addr()) {
		logger.Warn("LISTENING ON A NON-LOOPBACK ADDRESS: heimdall has no login, anyone who can reach it can change targets, credentials and suppressions; put it behind an SSO proxy",
			"addr", ln.Addr().String())
	}
	if onListen != nil {
		onListen(ln.Addr())
	}
	logger.Info("heimdall serve", "addr", ln.Addr().String(), "store", cfg.Store.Type, "jobs", backend.Name(), "secrets", keys != nil)

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

	// Job workers and the scheduler stop with the server.
	wctx, stopWorkers := context.WithCancel(ctx)
	var wg sync.WaitGroup
	if workers {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := backend.Run(wctx, service.NewJobHandler(deps)); err != nil {
				logger.Error("job workers stopped", "err", err)
			}
		}()
		go func() {
			defer wg.Done()
			if err := service.NewScheduler(deps).Run(wctx); err != nil && wctx.Err() == nil {
				logger.Error("scheduler stopped", "err", err)
			}
		}()
	} else if backend.Name() == "inline" {
		logger.Warn("--api-only with jobs.type inline: queued jobs will never run")
	}
	defer func() { stopWorkers(); wg.Wait() }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func isLoopback(addr net.Addr) bool {
	tcp, ok := addr.(*net.TCPAddr)
	return ok && tcp.IP.IsLoopback()
}
