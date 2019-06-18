package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func clean(cmd *cobra.Command, args []string) {
	mgr, err := newManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed: %s\n", err)
		os.Exit(1)
	}

	strict, err := cmd.Flags().GetBool("strict")
	if err != nil {
		strict = false
	}
	err = mgr.Load(false, strict)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed: %s\n", err)
		os.Exit(1)
	}

	var failed bool
	for _, cert := range mgr.Certs {
		err := cert.Key.Unlink()
		if err != nil {
			fmt.Fprintf(os.Stderr, "certmgr: failed to remove the private key for %s (%s)\n",
				cert, err)
			failed = true
		}

		err = cert.Cert.Unlink()
		if err != nil {
			fmt.Fprintf(os.Stderr, "certmgr: failed to remove the certificate for %s (%s)\n",
				cert, err)
			failed = true
		}

		if err == nil {
			fmt.Println("certmgr: successfully cleaned ", cert)
		}
	}

	if failed {
		fmt.Fprintf(os.Stderr, "certmgr: errors were encountered cleaning the certificates and private keys\n")
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
