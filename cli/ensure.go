package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var ensureTolerance = 3
var enableActions = false
var forceRegen = false
var allowZeroSpecs = false

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

	strict, err := cmd.Flags().GetBool("strict")
	if err != nil {
		strict = false
	}
	err = mgr.Load(false, strict)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed: %s\n", err)
		os.Exit(1)
	}

	if !allowZeroSpecs && len(mgr.Certs) == 0 {
		fmt.Fprint(os.Stderr, "Failed: No specs were found to process\n")
		os.Exit(1)
	}

	err = mgr.MustCheckCerts(ensureTolerance, enableActions, forceRegen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed: %s\n", err)
		os.Exit(1)
	}

	err = mgr.CheckDiskPKI()
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
	ensureCmd.Flags().BoolVarP(&forceRegen, "forceRegen", "", forceRegen, "if passed, ignore TTL checks and force regeneration of all specs")
	ensureCmd.Flags().BoolVarP(&allowZeroSpecs, "allowZeroSpecs", "0", allowZeroSpecs, "if passed, do not return a nonzero exit code if there were no specs found to process; defaults to failing if nothing is found")
}
