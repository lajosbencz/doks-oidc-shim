// Command doks-oidc-shim is the entry point for both the proxy and operator subcommands.
package main

import (
	"log/slog"
	"os"

	"github.com/lajosbencz/doks-oidc-shim/internal/logging"
	"github.com/spf13/cobra"
)

func main() {
	// Bootstrap logging from env so any line emitted before flag parsing uses
	// the operator-chosen format, not stdlib's default text-to-stderr.
	if err := logging.SetupFromEnv(); err != nil {
		slog.Error("invalid logging env", "err", err)
		os.Exit(1)
	}

	root := &cobra.Command{
		Use:           "doks-oidc-shim",
		Short:         "OIDC reverse proxy shim for managed Kubernetes",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return logging.SetupFromCmd(cmd)
		},
	}
	logging.RegisterFlags(root)

	root.AddCommand(newProxyCmd())
	root.AddCommand(newOperatorCmd())

	if err := root.Execute(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}
