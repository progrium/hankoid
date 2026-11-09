package main

import (
	"context"
	"fmt"
	"os"

	"github.com/progrium/hankoid/frontend"
	"github.com/progrium/hankoid/oidc"
	"github.com/spf13/cobra"
)

func newOIDCCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "oidc", Short: "OIDC provider tools"}
	var out string
	genkey := &cobra.Command{
		Use:   "genkey",
		Short: "Generate an RSA signing key (PEM) for oidc.signing_key_file or OIDC_SIGNING_KEY",
		RunE: func(cmd *cobra.Command, args []string) error {
			pem, err := oidc.GenerateKeyPEM()
			if err != nil {
				return err
			}
			if out == "" {
				_, err = os.Stdout.Write(pem)
				return err
			}
			if err := os.WriteFile(out, pem, 0o600); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "wrote %s\n", out)
			return nil
		},
	}
	genkey.Flags().StringVarP(&out, "out", "o", "", "write to this file (mode 0600) instead of stdout")
	cmd.AddCommand(genkey)
	cmd.AddCommand(newOIDCMigrateCommand())
	return cmd
}

func newOIDCMigrateCommand() *cobra.Command {
	var configFile string
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Create or update the hankoid schema used by oidc.store: postgres",
		Long: `Create or update the OIDC provider's tables in the hankoid schema of Hanko's database,
using the database section of the config (and Hanko's DATABASE_* variables).

The frontend also does this at startup when oidc.store is postgres, so this is only needed
when migrations run as a separate deployment step. It is safe to run repeatedly. Hanko's own
tables are migrated with "hankoid migrate up".`,
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := frontend.ReadConfigFile(configFile)
			if err != nil {
				return err
			}
			db, err := oidc.LoadDatabase(raw)
			if err != nil {
				return err
			}
			dsn, err := db.URL()
			if err != nil {
				return err
			}
			ctx := context.Background()
			pool, err := oidc.OpenPostgres(ctx, dsn)
			if err != nil {
				return err
			}
			defer pool.Close()
			applied, err := oidc.Migrate(ctx, pool)
			if err != nil {
				return err
			}
			if len(applied) == 0 {
				fmt.Fprintln(os.Stderr, "hankoid schema is up to date")
			}
			for _, v := range applied {
				fmt.Fprintf(os.Stderr, "applied migration %04d\n", v)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configFile, "config", frontend.DefaultConfigFile, "config file")
	return cmd
}
