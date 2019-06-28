package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/cloudflare/certmgr/cert"
	"github.com/cloudflare/certmgr/metrics"
	"github.com/cloudflare/certmgr/mgr"
	"github.com/cloudflare/certmgr/svcmgr"
	log "github.com/sirupsen/logrus"

	// needed for ensuring cfssl logs go through logrus
	cfssl_log "github.com/cloudflare/cfssl/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var logLevel string
var jsonLogging bool
var strict bool
var requireSpecs bool

var manager struct {
	Dir            string
	ServiceManager string
	Before         time.Duration
	Interval       time.Duration
}

func newManager() (*mgr.Manager, error) {
	return mgr.New(
		viper.GetString("dir"),
		viper.GetString("default_remote"),
		viper.GetString("svcmgr"),
		viper.GetDuration("before"),
		viper.GetDuration("interval"),
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
		certs = append(certs, x)
	}
	metrics.Start(
		viper.GetString("metrics_address"),
		viper.GetString("metrics_port"),
	)
	mgr.Server(strict)
}

// RootCmd this is our command processor for CLI interactions
var RootCmd = &cobra.Command{
	Use:   "certmgr",
	Short: "Manage TLS certificates for multiple services",
	Long:  ``,
	Run:   root,
}

// Execute execute our argument parser
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
	RootCmd.PersistentFlags().DurationVarP(&manager.Before, "before", "t", mgr.DefaultBefore, "how long before certificates expire to start renewing (in duration format)")
	RootCmd.PersistentFlags().DurationVarP(&manager.Interval, "interval", "i", mgr.DefaultInterval, "how long to sleep before checking for renewal (in duration format)")
	RootCmd.PersistentFlags().BoolVarP(&jsonLogging, "log.json", "", false, "if passed, logging will be in json")
	RootCmd.PersistentFlags().StringVarP(&logLevel, "log.level", "l", "info", "logging level.  Must be one [debug|info|warning|error]")
	RootCmd.PersistentFlags().BoolVar(&strict, "strict", false, "refuse to load certificate without valid renewal action defined")
	RootCmd.Flags().BoolVarP(&requireSpecs, "requireSpecs", "", false, "fail the daemon startup if no specs were found in the directory to watch")

	viper.BindPFlag("dir", RootCmd.PersistentFlags().Lookup("dir"))
	viper.BindPFlag("svcmgr", RootCmd.PersistentFlags().Lookup("svcmgr"))
	viper.BindPFlag("before", RootCmd.PersistentFlags().Lookup("before"))
	viper.BindPFlag("interval", RootCmd.PersistentFlags().Lookup("interval"))
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

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err != nil {
		log.Fatal(err)
	}

	if err := configureLogging(jsonLogging, logLevel); err != nil {
		log.Fatal(err)
	}
}

// cfsslLogAdaptor implements SyslogWriter interface, redirecting to logrus logging.
type cfsslLogAdaptor struct{}

func (cfssl *cfsslLogAdaptor) Debug(s string) {
	log.Debug(s)
}

func (cfssl *cfsslLogAdaptor) Info(s string) {
	log.Info(s)
}

func (cfssl *cfsslLogAdaptor) Warning(s string) {
	log.Warning(s)
}

func (cfssl *cfsslLogAdaptor) Err(s string) {
	log.Error(s)
}

func (cfssl *cfsslLogAdaptor) Crit(s string) {
	log.Error(s)
}

func (cfssl *cfsslLogAdaptor) Emerg(s string) {
	log.Error(s)
}

func configureLogging(jsonLogging bool, logLevel string) error {

	// install our shim for cfssl.
	cfssl_log.SetLogger(&cfsslLogAdaptor{})

	// configure json logging if requested.
	if jsonLogging {
		log.SetFormatter(&log.JSONFormatter{})
	}

	switch strings.ToLower(logLevel) {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warning":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	default:
		return fmt.Errorf("log level %s is not a valid level", logLevel)
	}
	return nil
}
