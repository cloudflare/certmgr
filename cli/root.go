package cli

import (
	"fmt"
	"os"

	"github.com/cloudflare/certmgr/metrics"
	"github.com/cloudflare/certmgr/mgr"
	"github.com/cloudflare/cfssl/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var logLevel string
var sync bool

var manager struct {
	Dir            string
	ServiceManager string
	Before         string
}

func newManager() (*mgr.Manager, error) {
	return mgr.New(
		viper.GetString("dir"),
		viper.GetString("default_remote"),
		viper.GetString("svcmgr"),
		viper.GetString("before"),
		viper.GetString("interval"),
	)
}

func root(cmd *cobra.Command, args []string) {
	mgr, err := newManager()
	if err != nil {
		log.Fatalf("certmgr: %s", err)
	}

	err = mgr.Load()
	if err != nil {
		log.Fatalf("certmgr: %s", err)
	}

	metrics.Start(viper.GetString("metrics_address"), viper.GetString("metrics_port"))
	mgr.Server(sync)
}

var RootCmd = &cobra.Command{
	Use:   "certmgr",
	Short: "Manage TLS certificates for multiple services",
	Long:  ``,
	Run:   root,
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	RootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "f", "", "config file (default is /etc/certmgr/certmgr.yaml)")
	RootCmd.PersistentFlags().StringVarP(&manager.Dir, "dir", "d", "", "directory containing certificate specs")
	RootCmd.PersistentFlags().StringVarP(&manager.ServiceManager, "svcmgr", "m", "", "service manager (one of systemd, sysv, or circus)")
	RootCmd.PersistentFlags().StringVarP(&manager.Before, "before", "t", "", "how long before certificates expire to start renewing (in the form Nh)")
	RootCmd.Flags().BoolVarP(&sync, "sync", "s", false, "the first certificate check should be synchronous")
	RootCmd.Flags().MarkHidden("sync")

	viper.BindPFlag("dir", RootCmd.PersistentFlags().Lookup("dir"))
	viper.BindPFlag("svcmgr", RootCmd.PersistentFlags().Lookup("svcmgr"))
	viper.BindPFlag("before", RootCmd.PersistentFlags().Lookup("before"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" { // enable ability to specify config file via flag
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("certmgr")      // name of config file (without extension)
		viper.AddConfigPath("/etc/certmgr") // adding home directory as first search path
	}

	viper.SetEnvPrefix("CERTMGR")
	viper.AutomaticEnv() // read in environment variables that match
	viper.SetDefault("loglevel", "info")

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		log.Info("certmgr: loading from config file ", viper.ConfigFileUsed())
	}
}
