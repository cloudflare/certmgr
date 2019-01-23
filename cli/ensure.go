package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var ensureTolerance = 3
var enableActions = false

var ensureCmd = &cobra.Command{
	Use:   "ensure",
	Short: "Ensure all certificate specs have matching keypairs.",
	Long: `Certificate manager will load all certificate specs, and ensure that the
TLS key pairs they identify exist, are valid, and that they are up-to-date.`,
	Run: Ensure,
}

func Ensure(cmd *cobra.Command, args []string) {
	mgr, err := newManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed: %s\n", err)
		os.Exit(1)
	}

	err = mgr.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed: %s\n", err)
		os.Exit(1)
	}

	err = mgr.MustCheckCerts(ensureTolerance, enableActions)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("OK")
}

func init() {
	RootCmd.AddCommand(ensureCmd)
	ensureCmd.Flags().IntVarP(&ensureTolerance, "tries", "n", ensureTolerance, "number of times to retry refreshing a certificate")
	ensureCmd.Flags().BoolVarP(&enableActions, "enableActions", "", enableActions, "if passed, run the certificates svcmgr actions; defaults to not running them")
}
