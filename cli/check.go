package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check the configuration file and certificate specs.",
	Long: `certmgr check will check and validate the certmgr configuration file
and validate the certificate specs. Note that this will verify that
the CA certificate can be fetched from the remote CA, but it doesn't
verify that the authentication key is valid, as this is currently only
checkable during the certificate provisioning process.`,
	Run: Check,
}

func Check(cmd *cobra.Command, args []string) {
	mgr, err := newManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed: %s\n", err)
		os.Exit(1)
	}

	err = mgr.Load(false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("OK")
}

func init() {
	RootCmd.AddCommand(checkCmd)
}
