package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
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
		&cert.SpecOptions{
			Remote:             viper.GetString("default_remote"),
			ServiceManagerName: viper.GetString("svcmgr"),
			Before:             viper.GetDuration("before"),
			Interval:           viper.GetDuration("interval"),
		},
	)
}

func createManager() (*mgr.Manager, error) {
	mgr, err := newManager()
	if err == nil {
		if err = mgr.Load(); err == nil {
			if requireSpecs && len(mgr.Certs) == 0 {
				err = errors.New("no specs were found, and --requireSpecs was passed")
			}
		}
	}

	return mgr, err
}
func root(cmd *cobra.Command, args []string) {
	currentMgr, err := createManager()
	if err != nil {
		log.Fatalf("certmgr: %s", err)
	}

	metrics.Start(
		viper.GetString("metrics_address"),
		viper.GetString("metrics_port"),
	)

	globalCtx, globalCancel := context.WithCancel(context.Background())
	defer globalCancel()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)

	runMgr := func(m *mgr.Manager) (chan struct{}, context.CancelFunc) {
		stopped := make(chan struct{}, 1)
		ctx, cancel := context.WithCancel(globalCtx)
		go func() {
			defer close(stopped)
			m.Server(ctx)
		}()
		return stopped, cancel
	}

	currentMgrDone, currentMgrCancel := runMgr(currentMgr)
Loop:
	for {
		select {
		case <-quit:
			log.Info("signaled to shutdown")
			globalCancel()
		case <-currentMgrDone:
			log.Info("manager has shutdown, exiting")
			break Loop
		case <-reload:
			log.Info("asked to reload, waiting for manager to shutdown")
			currentMgrCancel()
			<-currentMgrDone
			log.Info("reloading config")
			newMgr, err := createManager()
			if err != nil {
				log.Errorf("reload failed: %s", err)
				log.Error("continuing to run with old loaded configuration")
			} else {
				log.Infof("manager reloaded successfully")
				currentMgr = newMgr
			}
			log.Info("starting manager")
			currentMgrDone, currentMgrCancel = runMgr(currentMgr)
		}
	}
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
