package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cloudflare/certmgr/cert"
	"github.com/cloudflare/certmgr/cert/storage"
	"github.com/cloudflare/certmgr/certmgr/metrics"
	"github.com/cloudflare/certmgr/certmgr/mgr"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	// needed for ensuring cfssl logs go through zerolog
	cfssl_log "github.com/cloudflare/cfssl/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var requireSpecs bool

func newManager() (*mgr.Manager, error) {
	return mgr.New(
		viper.GetString("dir"),
		&mgr.ParsableSpecOptions{
			Remote:             viper.GetString("default_remote"),
			ServiceManagerName: viper.GetString("svcmgr"),
			SpecOptions: cert.SpecOptions{
				Before:        viper.GetDuration("before"),
				Interval:      viper.GetDuration("interval"),
				IntervalSplay: viper.GetDuration("interval_splay"),
				InitialSplay:  viper.GetDuration("initial_splay"),
			},
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
		log.Fatal().Err(err)
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
			log.Info().Msg("signalled to shutdown")
			globalCancel()
		case <-currentMgrDone:
			log.Info().Msg("manager has shutdown, exiting")
			break Loop
		case <-reload:
			log.Info().Msg("asked to reload, waiting for manager to shutdown")
			currentMgrCancel()
			<-currentMgrDone
			log.Info().Msg("reloading config")
			newMgr, err := createManager()
			if err != nil {
				log.Error().Err(err).Msg("reload failed, continuing to run with old configuration")
			} else {
				log.Info().Msg("manager reloaded successfully")
				currentMgr = newMgr
			}
			log.Info().Str("version", currentVersion).Msg("starting certmgr")
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
	RootCmd.PersistentFlags().StringP("dir", "d", "", "either the directory containing certificate specs, or the path to the spec file you wish to operate on")
	RootCmd.PersistentFlags().StringP("svcmgr", "m", "", fmt.Sprintf("service manager, must be one of: %s", strings.Join(storage.SupportedServiceBackends, ", ")))
	RootCmd.PersistentFlags().DurationP("before", "t", cert.DefaultBefore, "how long before certificates expire to start renewing (in duration format)")
	RootCmd.PersistentFlags().DurationP("interval", "i", cert.DefaultInterval, "how long to sleep before checking for renewal (in duration format)")
	RootCmd.PersistentFlags().DurationP("interval_splay", "", 0*time.Second, "a rng value of [0..intervalsplay] to add to each interval to randomize wake time")
	RootCmd.PersistentFlags().DurationP("initial_splay", "", 0*time.Second, "if specified, this is a rng value of [0..initial_splay] used to randomize the first wake period.  Subsequence wakes use interval configurables.")
	RootCmd.PersistentFlags().BoolP("log.json", "", false, "if passed, logging will be in json")
	RootCmd.PersistentFlags().StringP("log.level", "l", "info", "logging level.  Must be one [debug|info|warning|error]")
	RootCmd.Flags().BoolVarP(&requireSpecs, "requireSpecs", "", false, "fail the daemon startup if no specs were found in the directory to watch")

	viper.BindPFlag("dir", RootCmd.PersistentFlags().Lookup("dir"))
	viper.BindPFlag("svcmgr", RootCmd.PersistentFlags().Lookup("svcmgr"))
	viper.BindPFlag("before", RootCmd.PersistentFlags().Lookup("before"))
	viper.BindPFlag("interval", RootCmd.PersistentFlags().Lookup("interval"))
	viper.BindPFlag("interval_splay", RootCmd.PersistentFlags().Lookup("interval_splay"))
	viper.BindPFlag("initial_splay", RootCmd.PersistentFlags().Lookup("initial_splay"))
	viper.BindPFlag("log.json", RootCmd.PersistentFlags().Lookup("log.json"))
	viper.BindPFlag("log.level", RootCmd.PersistentFlags().Lookup("log.level"))
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
		log.Fatal().Err(err)
	}

	if err := configureLogging(viper.GetBool("log.json"), viper.GetString("log.level")); err != nil {
		log.Fatal().Err(err)
	}
}

func configureLogging(jsonLogging bool, logLevel string) error {
	// install our shim for cfssl.
	cfssl_log.SetLogger(&cfsslLogAdaptor{})

	// configure json logging if requested.
	if jsonLogging {
		log.Logger = zerolog.New(os.Stderr).With().Timestamp().Logger()
	} else {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}

	switch strings.ToLower(logLevel) {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)

		// In debug mode, we also add a filename and line number to any log calls
		log.Logger = log.With().Caller().Logger()
		log.Debug().Msg("enabled debug mode with caller logging")
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warning":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		return fmt.Errorf("log level %s is not a valid level", logLevel)
	}
	return nil
}
