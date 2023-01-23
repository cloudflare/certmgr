package cmd

import (
	"github.com/cloudflare/cfssl/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check the configuration file and certificate specs.",
	Long: `certmgr check will check and validate the certmgr configuration file
and validate the certificate specs. Note that this will verify that
the CA certificate can be fetched from the remote CA, but it doesn't
verify that the authentication key is valid, as this is currently only
checkable during the certificate provisioning process.`,
	Run: check,
}

func check(cmd *cobra.Command, args []string) {
	if err := viper.ReadInConfig(); err != nil {
		log.Fatal(err)
	}
	mgr, err := newManager()
	if err != nil {
		log.Fatalf("Failed: %s", err)
	}

	err = mgr.Load()
	if err != nil {
		log.Fatalf("Failed: %s", err)
	}
}

func init() {
	RootCmd.AddCommand(checkCmd)
}
