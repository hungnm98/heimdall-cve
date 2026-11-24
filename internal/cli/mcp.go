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

	"github.com/hungnm98/heimdall-cve/internal/app"
	"github.com/hungnm98/heimdall-cve/internal/config"
	"github.com/hungnm98/heimdall-cve/internal/mcpserver"
	"github.com/hungnm98/heimdall-cve/internal/service"
	"github.com/spf13/cobra"
)

func newMCPCmd(g *globalFlags) *cobra.Command {
	var transport, listen string
	var allowWrites, allowNotify, allowScan bool
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Serve Heimdall to AI agents over the Model Context Protocol",
		Long: "Expose scan results, the dependency inventory and agent intelligence as MCP tools,\n" +
			"plus the routines in prompts/ as MCP prompts.\n\n" +
			"Write tools are disabled unless enabled here or in the config (mcp.allow_*): the flags\n" +
			"can only enable. Scan tools only queue jobs: `heimdall serve` or `heimdall worker`\n" +
			"executes them (this command runs no job workers). With --transport stdio, stdout\n" +
			"carries the protocol and logs go to stderr.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if transport != "stdio" && transport != "http" {
				return fmt.Errorf("--transport must be stdio or http, got %q", transport)
			}
			cfg, err := config.Load(g.configFile)
			if err != nil {
				return err
			}
			cfg.MCP.AllowAgentWrites = cfg.MCP.AllowAgentWrites || allowWrites
			cfg.MCP.AllowNotify = cfg.MCP.AllowNotify || allowNotify
			cfg.MCP.AllowScan = cfg.MCP.AllowScan || allowScan
			if listen != "" {
				cfg.MCP.Listen = listen
			}
			logger, err := g.logger(cmd.ErrOrStderr()) // never stdout: it is the stdio transport
			if err != nil {
				return err
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
			defer rt.Jobs.Close()
			svcs := service.New(rt.Deps)
			if svcs.Intel == nil {
				logger.Warn("the store has no agent intelligence: inventory, analysis queue, submit_* and notify_user tools are unavailable", "store", cfg.Store.Type)
			}
			if cfg.MCP.AllowScan && rt.Jobs.Name() == "inline" {
				logger.Warn("scan tools enabled with jobs.type inline: queued jobs only run in this process, which runs no workers; use a shared queue (asynq) and `heimdall worker`")
			}
			srv := mcpserver.New(svcs, mcpserver.Options{
				AllowScan: cfg.MCP.AllowScan, Config: cfg, Audit: rt.Deps.Catalog, Logger: logger, Version: Version,
			})
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			logger.Info("heimdall mcp", "transport", transport, "store", cfg.Store.Type,
				"allow_scan", cfg.MCP.AllowScan, "allow_agent_writes", cfg.MCP.AllowAgentWrites, "allow_notify", cfg.MCP.AllowNotify)
			if transport == "stdio" {
				err := srv.RunStdio(ctx)
				if errors.Is(err, context.Canceled) {
					return nil
				}
				return err
			}
			return serveMCPHTTP(ctx, srv, cfg.MCP.Listen, logger)
		},
	}
	f := cmd.Flags()
	f.StringVar(&transport, "transport", "stdio", "stdio | http (streamable HTTP at /mcp)")
	f.StringVar(&listen, "listen", "", "HTTP listen address (default mcp.listen, 127.0.0.1:8090)")
	f.BoolVar(&allowWrites, "allow-agent-writes", false, "enable submit_advisory and submit_analysis")
	f.BoolVar(&allowNotify, "allow-notify", false, "enable notify_user")
	f.BoolVar(&allowScan, "allow-scan", false, "enable scan_target and scan_repo (queue jobs)")
	return cmd
}

func serveMCPHTTP(ctx context.Context, srv *mcpserver.Server, addr string, logger *slog.Logger) error {
	mux := http.NewServeMux()
	mux.Handle("/mcp", srv.HTTPHandler())
	hs := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelWarn)}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if !isLoopback(ln.Addr()) {
		logger.Warn("MCP LISTENING ON A NON-LOOPBACK ADDRESS: there is no authentication; put it behind an authenticating proxy", "addr", ln.Addr().String())
	}
	logger.Info("mcp http", "url", "http://"+ln.Addr().String()+"/mcp")
	errc := make(chan error, 1)
	go func() { errc <- hs.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := hs.Shutdown(shutdownCtx); err != nil {
		return err
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
