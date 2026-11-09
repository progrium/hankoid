// Command hankoid is the Hanko CLI extended with this project's commands.
//
// It reuses the upstream Hanko subcommands and replaces "serve" with a version that adds a
// "frontend" component for the admin web UI. Build with -tags dev to add the "dev" command.
package main

import (
	"fmt"
	"log"
	"runtime/debug"

	"github.com/progrium/hankoid"
	"github.com/spf13/cobra"
	"github.com/teamhanko/hanko/backend/v3/cmd/cleanup"
	hankoConfig "github.com/teamhanko/hanko/backend/v3/cmd/config"
	"github.com/teamhanko/hanko/backend/v3/cmd/isready"
	"github.com/teamhanko/hanko/backend/v3/cmd/jwk"
	"github.com/teamhanko/hanko/backend/v3/cmd/jwt"
	"github.com/teamhanko/hanko/backend/v3/cmd/migrate"
	"github.com/teamhanko/hanko/backend/v3/cmd/schema"
	"github.com/teamhanko/hanko/backend/v3/cmd/siwa"
	"github.com/teamhanko/hanko/backend/v3/cmd/user"
)

// registrars lets build-tagged files add commands.
var registrars []func(*cobra.Command)

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hankoid",
		Short: "Hanko with an admin frontend",
		Long: `hankoid is the Hanko server and CLI extended with an admin frontend.

Copyright (C) 2026 Jeff Lindsay. Licensed under the GNU AGPLv3 and comes with
ABSOLUTELY NO WARRANTY. Source: ` + hankoid.SourceURL + `
Run "hankoid license" for the full license text.`,
	}

	migrate.RegisterCommands(cmd)
	registerServe(cmd)
	isready.RegisterCommands(cmd)
	jwk.RegisterCommands(cmd)
	jwt.RegisterCommands(cmd)
	cmd.AddCommand(newVersionCommand())
	cmd.AddCommand(newLicenseCommand())
	cmd.AddCommand(newOIDCCommand())
	registerCredCommands(cmd)
	user.RegisterCommands(cmd)
	siwa.RegisterCommands(cmd)
	schema.RegisterCommands(cmd)
	cleanup.RegisterCommands(cmd)
	hankoConfig.RegisterCommands(cmd)

	for _, register := range registrars {
		register(cmd)
	}
	return cmd
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		log.Fatal(err)
	}
}

// version is set at build time with -ldflags "-X main.version=...".
var version = ""

// newVersionCommand replaces upstream's, whose build_info package embeds a version.txt that
// isn't included in the published module.
func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version and exit",
		Run: func(cmd *cobra.Command, args []string) {
			v, hanko := version, "unknown"
			if bi, ok := debug.ReadBuildInfo(); ok {
				if v == "" {
					v = bi.Main.Version
				}
				for _, dep := range bi.Deps {
					if dep.Path == "github.com/teamhanko/hanko/backend/v3" {
						hanko = dep.Version
					}
				}
			}
			fmt.Printf("hankoid %s (hanko %s)\nLicensed under the GNU AGPLv3. Source: %s\n", v, hanko, hankoid.SourceURL)
		},
	}
}

func newLicenseCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "license",
		Short: "Print the license (GNU AGPLv3) and exit",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(hankoid.License)
		},
	}
}
