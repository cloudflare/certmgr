package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var currentVersion = "2.0.1"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information.",
	Long:  `certmgr version will return the current version of certmgr.`,
	Run:   version,
}

func version(cmd *cobra.Command, args []string) {
	fmt.Println("certmgr version", currentVersion)
	fmt.Println("	built with Go", runtime.Version())
	fmt.Printf(`
	Configuration:
	--------------
	certspec directory:	%s
	default remote:		%s
	service manager:	%s
	renew before:		%s
	check interval:		%s
`, viper.GetString("dir"), viper.GetString("default_remote"),
		viper.GetString("svcmgr"), viper.GetString("before"), viper.GetString("interval"))
}

func init() {
	RootCmd.AddCommand(versionCmd)
}
