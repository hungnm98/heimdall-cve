package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hungnm98/heimdall-cve/internal/app"
	"github.com/hungnm98/heimdall-cve/internal/config"
	"github.com/hungnm98/heimdall-cve/internal/secret"
	"github.com/hungnm98/heimdall-cve/internal/service"
	"github.com/hungnm98/heimdall-cve/internal/store"
	"github.com/spf13/cobra"
)

// oldMasterKeysEnv holds the retired master keys during a rotation.
const oldMasterKeysEnv = "HEIMDALL_MASTER_KEY_OLD"

func newSecretsCmd(g *globalFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "secrets", Short: "Manage secrets stored in the web app"}
	rotate := &cobra.Command{
		Use:   "rotate-kek",
		Short: "Re-wrap every stored secret under the current master key",
		Long: "Re-wraps each secret's data key with the new master key (secrets.master_key_env, default\n" +
			"HEIMDALL_MASTER_KEY). The retired keys go in " + oldMasterKeysEnv + " (comma-separated, base64).\n" +
			"Secret values are not re-encrypted. Safe to run again: secrets already under the new key are skipped.",
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
			newKey, err := secret.Resolve(cfg.Secrets.MasterKeyEnv, cfg.Secrets.MasterKeyFile)
			if err != nil {
				return fmt.Errorf("new master key: %w", err)
			}
			oldKeys, err := secret.Resolve(oldMasterKeysEnv, "")
			if err != nil {
				return fmt.Errorf("retired master keys: %w", err)
			}
			ring := []string{newKey}
			for _, k := range strings.Split(oldKeys, ",") {
				if k = strings.TrimSpace(k); k != "" {
					ring = append(ring, k)
				}
			}
			keys, err := secret.NewKeyRing(ring...)
			if err != nil {
				return err
			}
			s, err := app.OpenStore(cfg, logger)
			if err != nil {
				return err
			}
			defer s.Close()
			cat, ok := s.(store.Catalog)
			if !ok {
				return errors.New("store " + cfg.Store.Type + " does not hold web app secrets")
			}
			n, err := service.RotateKEK(cmd.Context(), cat, keys)
			fmt.Fprintf(cmd.OutOrStdout(), "re-wrapped %d secret(s) under master key %s\n", n, keys.CurrentID())
			if err != nil {
				return fmt.Errorf("some secrets were not rotated:\n%w", err)
			}
			return nil
		},
	}
	cmd.AddCommand(rotate)
	return cmd
}
