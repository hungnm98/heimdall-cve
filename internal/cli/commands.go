package cli

import (
	"fmt"
	"sort"

	"github.com/hungnm98/heimdall-cve/internal/app"
	"github.com/hungnm98/heimdall-cve/internal/config"
	"github.com/hungnm98/heimdall-cve/internal/registry"
	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "heimdall %s (%s)\n", Version, Commit)
		},
	}
}

func newConfigCmd(g *globalFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Inspect configuration"}
	validate := &cobra.Command{
		Use:   "validate",
		Short: "Load and validate the config, then check every referenced plugin is compiled in",
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
				return fmt.Errorf("config is valid but plugins failed:\n%w", err)
			}
			defer a.Close()
			fmt.Fprint(cmd.OutOrStdout(), cfg.Summary())
			fmt.Fprintln(cmd.OutOrStdout(), "config OK")
			return nil
		},
	}
	cmd.AddCommand(validate)
	return cmd
}

func newDBCmd(g *globalFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "db", Short: "Database maintenance"}
	migrate := &cobra.Command{
		Use:   "migrate",
		Short: "Create or upgrade the store schema (safe to run concurrently and repeatedly)",
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
			s, err := app.OpenStore(cfg, logger)
			if err != nil {
				return err
			}
			defer s.Close()
			if err := s.Migrate(cmd.Context()); err != nil {
				return fmt.Errorf("migrate: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "store %s migrated\n", cfg.Store.Type)
			return nil
		},
	}
	cmd.AddCommand(migrate)
	return cmd
}

func newPluginsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "plugins",
		Short: "List plugins compiled into this binary",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			cat := registry.Catalog()
			kinds := make([]string, 0, len(cat))
			for k := range cat {
				kinds = append(kinds, k)
			}
			sort.Strings(kinds)
			for _, k := range kinds {
				names := cat[k]
				if len(names) == 0 {
					names = []string{"-"}
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%-22s %v\n", k, names)
			}
		},
	}
}
