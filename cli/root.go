package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/cloudflare/certmgr/cert"
	"github.com/cloudflare/certmgr/metrics"
	"github.com/cloudflare/certmgr/mgr"
	"github.com/cloudflare/certmgr/svcmgr"
	"github.com/cloudflare/cfssl/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var logLevel string
var debug, strict bool
var requireSpecs bool

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
	strict, err := cmd.Flags().GetBool("strict")
	if err != nil {
		strict = false
	}
	err = mgr.Load(false, strict)
	if err != nil {
		log.Fatalf("certmgr: %s", err)
	}

	if requireSpecs && len(mgr.Certs) == 0 {
		log.Fatal("certmgr: no specs were found, and --requireSpecs was passed")
	}

	// bit of a hack- metrics should instead see the mgr
	// so changes in certs count are properly reflected.
	certs := []*cert.Spec{}
	for _, x := range mgr.Certs {
		certs = append(certs, x.Spec)
	}
	metrics.Start(
		viper.GetString("metrics_address"),
		viper.GetString("metrics_port"),
		viper.GetString("index_extra_html"),
		certs,
	)
	mgr.Server(strict)
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
	RootCmd.PersistentFlags().StringVarP(&manager.Dir, "dir", "d", "", "either the directory containing certificate specs, or the path to the spec file you wish to operate on")
	backends := []string{}
	for backend := range svcmgr.SupportedBackends {
		backends = append(backends, backend)
	}
	sort.Strings(backends)
	RootCmd.PersistentFlags().StringVarP(&manager.ServiceManager, "svcmgr", "m", "", fmt.Sprintf("service manager, must be one of: %s", strings.Join(backends, ", ")))
	RootCmd.PersistentFlags().StringVarP(&manager.Before, "before", "t", "", "how long before certificates expire to start renewing (in the form Nh)")
	RootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "enable debug mode")
	RootCmd.PersistentFlags().BoolVar(&strict, "strict", false, "refuse to load certificate without valid renewal action defined")
	RootCmd.Flags().BoolVarP(&requireSpecs, "requireSpecs", "", false, "fail the daemon startup if no specs were found in the directory to watch")

	viper.BindPFlag("dir", RootCmd.PersistentFlags().Lookup("dir"))
	viper.BindPFlag("svcmgr", RootCmd.PersistentFlags().Lookup("svcmgr"))
	viper.BindPFlag("before", RootCmd.PersistentFlags().Lookup("before"))
	viper.BindPFlag("debug", RootCmd.PersistentFlags().Lookup("debug"))
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

	viper.SetDefault("index_extra_html", "")

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		log.Info("certmgr: loading from config file ", viper.ConfigFileUsed())
	}

	if debug {
		log.Level = log.LevelDebug
		log.Debug("debug mode enabled")
	}
}
