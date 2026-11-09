package main

import (
	"log"
	"sync"

	"github.com/labstack/echo-contrib/echoprometheus"
	"github.com/progrium/hankoid/frontend"
	"github.com/spf13/cobra"
	"github.com/teamhanko/hanko/backend/v3/cmd/serve"
	"github.com/teamhanko/hanko/backend/v3/config"
	"github.com/teamhanko/hanko/backend/v3/crypto/jwk/local_db"
	"github.com/teamhanko/hanko/backend/v3/mapper"
	"github.com/teamhanko/hanko/backend/v3/persistence"
	"github.com/teamhanko/hanko/backend/v3/saml"
	"github.com/teamhanko/hanko/backend/v3/server"
)

func registerFrontendFlags(cmd *cobra.Command, a *frontend.Addrs) {
	cmd.Flags().StringVar(&a.Listen, "frontend-listen", "", "frontend listen address (default: server.frontend.address, or 127.0.0.1:8080)")
	cmd.Flags().StringVar(&a.Admin, "frontend-admin", "", "admin API URL for the frontend (default: from server.admin.address)")
	cmd.Flags().StringVar(&a.Public, "frontend-public", "", "public API URL for the frontend (default: from server.public.address)")
}

// startFrontend loads the frontend and OIDC provider config and serves the frontend.
func startFrontend(configFile string, a frontend.Addrs, wg *sync.WaitGroup) {
	defer wg.Done()
	cfg, err := frontend.LoadConfig(configFile)
	if err != nil {
		log.Fatal(err)
	}
	up, err := cfg.Resolve(a)
	if err != nil {
		log.Fatal(err)
	}
	extra, label, err := oidcHandlers(cfg, up)
	if err != nil {
		log.Fatal(err)
	}
	var labelers []frontend.NextLabeler
	if label != nil {
		labelers = append(labelers, label)
	}
	log.Fatal(frontend.Serve(cfg, up, extra, labelers...))
}

func newServeFrontendCommand() *cobra.Command {
	var (
		configFile string
		f          frontend.Addrs
	)
	cmd := &cobra.Command{
		Use:   "frontend",
		Short: "Start the frontend (sign-in page and admin UI), proxying to a running admin and public server",
		Long: `Start the frontend, proxying to a running admin and public server.

Routes: /signin (Hanko sign-in), /admin/ (admin UI, limited by server.frontend.admin_access),
/admin/api/* (admin API proxy), /oidc/* (OIDC provider, when oidc.clients is configured),
and everything else to the public API.

Only the server, session.cookie, secrets.keys, and oidc sections of the config are read,
so the database need not be configured, unless oidc.store is postgres: then the database
section is read too, and the hankoid schema is migrated at startup.`,
		Run: func(cmd *cobra.Command, args []string) {
			var wg sync.WaitGroup
			wg.Add(1)
			go startFrontend(configFile, f, &wg)
			wg.Wait()
		},
	}
	cmd.Flags().StringVar(&configFile, "config", config.DefaultConfigFilePath, "config file")
	registerFrontendFlags(cmd, &f)
	return cmd
}

// newServeAllCommand mirrors upstream "serve all" and also starts the frontend.
func newServeAllCommand() *cobra.Command {
	var (
		configFile                string
		authenticatorMetadataFile string
		noFrontend                bool
		f                         frontend.Addrs
	)
	cmd := &cobra.Command{
		Use:   "all",
		Short: "Start the public, admin, and frontend portions of the hanko server",
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := config.Load(&configFile)
			if err != nil {
				log.Fatal(err)
			}
			authenticatorMetadata := mapper.LoadAuthenticatorMetadata(&authenticatorMetadataFile)
			dbConnection, err := persistence.NewConnection(cfg.Database)
			if err != nil {
				log.Fatal(err)
			}
			persister := persistence.New(dbConnection)

			log.Println("Syncing SAML providers from config to database...")
			if err := saml.SyncProviderConfigToDatabase(cfg, persister); err != nil {
				log.Printf("SAML config sync failed: %v", err)
			}
			if err := local_db.SyncSecretKeys(cfg, persister); err != nil {
				log.Fatalf("Failed to sync secret keys: %v", err)
			}

			var wg sync.WaitGroup
			wg.Add(3)
			prometheus := echoprometheus.NewMiddleware("hanko")
			go server.StartPublic(cfg, &wg, persister, prometheus, authenticatorMetadata)
			go server.StartAdmin(cfg, &wg, persister, prometheus)
			go server.StartManagement(cfg, &wg, persister)
			if !noFrontend {
				wg.Add(1)
				go startFrontend(configFile, f, &wg)
			}
			wg.Wait()
		},
	}
	cmd.Flags().StringVar(&configFile, "config", config.DefaultConfigFilePath, "config file")
	cmd.Flags().StringVar(&authenticatorMetadataFile, "auth-meta", "", "authenticator metadata file")
	cmd.Flags().BoolVar(&noFrontend, "no-frontend", false, "do not start the frontend")
	registerFrontendFlags(cmd, &f)
	return cmd
}

func registerServe(parent *cobra.Command) {
	cmd := serve.NewServeCommand()
	parent.AddCommand(cmd)
	cmd.AddCommand(serve.NewServePublicCommand())
	cmd.AddCommand(serve.NewServeAdminCommand())
	cmd.AddCommand(serve.NewServeManagementCommand())
	cmd.AddCommand(newServeFrontendCommand())
	cmd.AddCommand(newServeAllCommand())
}
