package cmd

import (
	"os"

	"github.com/cloudflare/certmgr/cert/storage"
	"github.com/cloudflare/cfssl/log"
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
		log.Fatalf("failed creating manager", err)
	}

	err = mgr.Load()
	if err != nil {
		log.Fatalf("failed loading manager: %s", err)
	}

	if !allowZeroSpecs && len(mgr.Certs) == 0 {
		log.Fatalf("Failed: No specs were found to process")
	}

	failedSpecs := false
	for _, cert := range mgr.Certs {
		if !enableActions {
			switch t := cert.Storage.(type) {
			case *storage.FileBackend: // nothing to do here, just noting it for completeness
			case *storage.FileServiceNotifier:
				log.Debugf("disabling actions for %s", cert)
				cert.Storage = t.FileBackend
			case *storage.FileCommandNotifier:
				log.Debugf("disabling actions for %s", cert)
				cert.Storage = t.FileBackend
			default:
				log.Errorf("spec %s has a storage backend we do not know how to work with; this is an internal certmgr bug", cert)
				continue
			}
		}
		log.Infof("backend is %s", cert.Storage)

		if forceRegen {
			err = cert.ForceUpdate()
		} else {
			err = cert.UpdateIfNeeded()
		}
		if err != nil {
			log.Errorf("Failed processing spec %s due to %s", cert, err)
			failedSpecs = true
		}
	}
	if !failedSpecs {
		log.Info("processed specs without issue")
		os.Exit(0)
	}
	log.Error("not all specs were processed successfully")
	os.Exit(1)
}

func init() {
	RootCmd.AddCommand(ensureCmd)
	ensureCmd.Flags().BoolVarP(&enableActions, "enableActions", "", enableActions, "if passed, run the certificates svcmgr actions; defaults to not running them")
	ensureCmd.Flags().BoolVarP(&forceRegen, "forceRegen", "", forceRegen, "if passed, ignore TTL checks and force regeneration of all specs")
	ensureCmd.Flags().BoolVarP(&allowZeroSpecs, "allowZeroSpecs", "0", allowZeroSpecs, "if passed, do not return a nonzero exit code if there were no specs found to process; defaults to failing if nothing is found")
}
