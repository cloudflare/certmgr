package cmd

import (
	"os"

	"github.com/cloudflare/certmgr/cert/storage"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var enableActions = false
var forceRegen = false
var allowZeroSpecs = false

var ensureCmd = &cobra.Command{
	Use:   "ensure",
	Short: "Ensure all certificate specs have matching keypairs.",
	Long: `Certificate manager will load all certificate specs, and ensure that the
TLS key pairs they identify exist, are valid, and that they are up-to-date.`,
	Run: ensure,
}

func ensure(cmd *cobra.Command, args []string) {
	mgr, err := newManager()
	if err != nil {
		log.Fatal().Err(err).Msg("failed creating manager")
	}

	err = mgr.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("failed loading manager")
	}

	if !allowZeroSpecs && len(mgr.Certs) == 0 {
		log.Fatal().Msg("no specs were found to process")
	}

	failedSpecs := false
	for _, cert := range mgr.Certs {
		log := log.With().Str("spec", cert.Name).Logger()
		if !enableActions {
			switch t := cert.Storage.(type) {
			case *storage.FileBackend: // nothing to do here, just noting it for completeness
			case *storage.FileServiceNotifier:
				log.Debug().Msg("disabling actions")
				cert.Storage = t.FileBackend
			case *storage.FileCommandNotifier:
				log.Debug().Msg("disabling actions")
				cert.Storage = t.FileBackend
			default:
				log.Error().Msg("certmgr has a storage backend we do not know how to work with; this is an internal certmgr bug")
				continue
			}
		}
		log.Info().Bool("force", forceRegen).Msg("processing spec")
		if forceRegen {
			err = cert.ForceUpdate()
		} else {
			err = cert.UpdateIfNeeded()
		}
		if err != nil {
			log.Error().Err(err).Msg("failed processing spec")
			failedSpecs = true
		}
	}
	if !failedSpecs {
		log.Info().Msg("processed all specs without issue")
		os.Exit(0)
	}
	log.Error().Msg("not all specs were processed successfully")
	os.Exit(1)
}

func init() {
	RootCmd.AddCommand(ensureCmd)
	ensureCmd.Flags().BoolVarP(&enableActions, "enableActions", "", enableActions, "if passed, run the certificates svcmgr actions; defaults to not running them")
	ensureCmd.Flags().BoolVarP(&forceRegen, "forceRegen", "", forceRegen, "if passed, ignore TTL checks and force regeneration of all specs")
	ensureCmd.Flags().BoolVarP(&allowZeroSpecs, "allowZeroSpecs", "0", allowZeroSpecs, "if passed, do not return a nonzero exit code if there were no specs found to process; defaults to failing if nothing is found")
}
