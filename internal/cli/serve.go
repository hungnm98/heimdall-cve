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
	"syscall"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/api"
	"github.com/hungnm98/heimdall-cve/internal/app"
	"github.com/hungnm98/heimdall-cve/internal/auth"
	"github.com/hungnm98/heimdall-cve/internal/config"
	"github.com/hungnm98/heimdall-cve/internal/service"
	"github.com/hungnm98/heimdall-cve/internal/store"
	"github.com/hungnm98/heimdall-cve/internal/vcs"
	"github.com/hungnm98/heimdall-cve/internal/webui"
	"github.com/spf13/cobra"
)

func newServeCmd(g *globalFlags) *cobra.Command {
	var listen string
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
			return serve(cmd.Context(), a, nil)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "", "listen address (default server.listen, 127.0.0.1:8080)")
	return cmd
}

// serve runs the HTTP server until ctx is canceled or SIGINT/SIGTERM.
// onListen, if set, receives the bound address (tests listen on port 0).
func serve(ctx context.Context, a *app.App, onListen func(net.Addr)) error {
	cfg, logger := a.Config, a.Logger
	cat, ok := a.Store.(store.Catalog)
	if !ok {
		return fmt.Errorf("store %q does not implement the catalog needed by serve (targets, jobs, audit); use a store that does (memory now, postgres once its catalog lands)", cfg.Store.Type)
	}
	keys, err := a.MasterKeys()
	if err != nil {
		return fmt.Errorf("master key: %w", err)
	}
	if keys == nil {
		logger.Warn("no master key configured: secrets cannot be entered in the UI", "env", cfg.Secrets.MasterKeyEnv, "file", cfg.Secrets.MasterKeyFile)
	}
	backend, err := a.NewJobs()
	if err != nil {
		return err
	}
	defer backend.Close()

	deps := service.Deps{
		Config: cfg, Store: a.Store, Catalog: cat, Jobs: backend,
		Scanner:     nil, // the scan pipeline and job worker arrive in Phase 2
		Keys:        keys,
		Secrets:     a.Deps.Secrets,
		ProviderFor: a.CatalogProviderFor(cat),
		Notifiers:   a.Notifiers, SourceKinds: a.SourceKinds(),
		Logger: logger, Now: time.Now,
	}
	if err := service.SyncConfig(ctx, deps); err != nil {
		logger.Warn("config sync incomplete", "err", err)
	}
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
