package cmd

import (
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func clean(cmd *cobra.Command, args []string) {
	mgr, err := newManager()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create manager")
	}

	err = mgr.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load specs")
	}

	var failed bool
	for _, cert := range mgr.Certs {
		if err := cert.Storage.Wipe(); err != nil {
			log.Error().Str("spec", cert.Name).Err(err).Msg("failed to clean spec")
		} else {
			log.Info().Str("spec", cert.Name).Msg("successfully cleaned spec")
		}
	}

	if failed {
		log.Warn().Msg("errors were encountered cleaning the certificates and private keys")
		os.Exit(1)
	}
}

var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Remove all certificates and private keys managed by certmgr.",
	Long: `certmgr clean will load the config file and certificate specs, and attempt
to remove any generated certificates and private keys.`,
	Run: clean,
}

func init() {
	RootCmd.AddCommand(cleanCmd)
}
