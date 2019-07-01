package cli

import (
	"os"

	"github.com/cloudflare/cfssl/log"
	"github.com/spf13/cobra"
)

func clean(cmd *cobra.Command, args []string) {
	mgr, err := newManager()
	if err != nil {
		log.Fatalf("Failed: %s", err)
	}

	err = mgr.Load()
	if err != nil {
		log.Fatalf("failed: %s", err)
	}

	var failed bool
	for _, cert := range mgr.Certs {
		err := cert.Key.Unlink()
		if err != nil {
			log.Errorf("failed to remove the private key for %s (%s)", cert, err)
			failed = true
		}

		err = cert.Cert.Unlink()
		if err != nil {
			log.Errorf("failed to remove the certificate for %s (%s)", cert, err)
			failed = true
		}

		if err == nil {
			log.Infof("successfully cleaned %s", cert)
		}
	}

	if failed {
		log.Warningf("errors were encountered cleaning the certificates and private keys")
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
