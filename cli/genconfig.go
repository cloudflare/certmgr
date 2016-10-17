package cli

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	yaml "gopkg.in/yaml.v2"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var force bool

const (
	defaultConfigFile     = "/etc/certmgr/certmgr.yaml"
	defaultDir            = "/etc/certmgr.d"
	defaultServiceManager = "systemd"
	defaultBefore         = "72h"
	defaultInterval       = "1h"
	defaultMetricsAddr    = "localhost"
	defaultMetricsPort    = "8080"
)

type config struct {
	// Dir is the directory containing the certificate specs.
	Dir string `json:"certspecs" yaml:"certspecs"`

	// ServiceManager is the service manager used to restart a
	// service.
	ServiceManager string `json:"service_manager" yaml:"service_manager"`

	// Before is how long before the cert expires to start
	// attempting to renew it.
	Before string `json:"before" yaml:"before"`

	// Interval is how often to update the NextExpires metric.
	Interval string `json:"interval" yaml:"interval"`

	// MetricsAddr contains the metrics server address.
	MetricsAddr string `json:"metrics_address" yaml:"metrics_address"`

	// MetricsPort contains the metrics server port.
	MetricsPort string `json:"metrics_port" yaml:"metrics_port"`
}

func genConfig(cmd *cobra.Command, args []string) {
	var manager = &config{
		MetricsAddr: defaultMetricsAddr,
		MetricsPort: defaultMetricsPort,
	}

	manager.Dir = viper.GetString("dir")
	if manager.Dir == "" {
		manager.Dir = defaultDir
	}

	manager.ServiceManager = viper.GetString("svcmanager")
	if manager.ServiceManager == "" {
		manager.ServiceManager = defaultServiceManager
	}

	manager.Before = viper.GetString("before")
	if manager.Before == "" {
		manager.Before = defaultBefore
	}

	manager.Interval = viper.GetString("interval")
	if manager.Interval == "" {
		manager.Interval = defaultInterval
	}

	confFile := viper.ConfigFileUsed()
	if confFile == "" {
		flag := cmd.PersistentFlags().Lookup("config")
		if flag == nil {
			confFile = defaultConfigFile
		} else {
			confFile = flag.Value.String()
		}
	}

	_, err := os.Stat(confFile)
	if err == nil {
		if !force {
			fmt.Fprintf(os.Stderr, "certmgr: configuration file %s exists and --force was not specified.\n", confFile)
			os.Exit(1)
		}
		fmt.Printf("certmgr: overwriting existing configuration file %s\n", confFile)
	}

	out, err := yaml.Marshal(manager)
	if err != nil {
		fmt.Fprintf(os.Stderr, "certmgr: failed to marshal configuration (err=%s)\n", err)
		os.Exit(1)
	}

	confDir := filepath.Dir(confFile)
	_, err = os.Stat(confDir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("certmgr: creating configuration file directory %s\n", confDir)
			err = os.MkdirAll(confDir, 0755)
			if err != nil {
				fmt.Fprintf(os.Stderr, "certmgr: failed to create %s (err=%s)\n",
					confDir, err)
				os.Exit(1)
			}
		} else {
			fmt.Fprintf(os.Stderr, "certmgr: error creating configuration file directory (err=%s)\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("certmgr: writing config file %s\n", confFile)
	fmt.Printf("-----\n%s\n-----\n", string(out))
	err = ioutil.WriteFile(confFile, out, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "certmgr: error writing configuration file (err=%s)\n", err)
		os.Exit(1)
	}

	fmt.Printf("certmgr: creating certificate spec directory %s\n", manager.Dir)
	err = os.MkdirAll(manager.Dir, 0755)
	if err != nil {
		fmt.Fprintf(os.Stderr, "certmgr: failed to create certificate spec directory %s (err=%s)\n", manager.Dir, err)
		os.Exit(1)
	}
}

var genconfigCmd = &cobra.Command{
	Use:   "genconfig",
	Short: "Generate a default config and the cert spec dir.",
	Long: fmt.Sprintf(`Generates a default configuration. The command line flags can be used
to set the parameters for the config file. For example, to use the
SysV init system to manage services,

	certmgr genconfig -m sysv

The defaults are:

	+ configuration file path (-f): %s
	+ certificate spec directory (-d): %s
	+ service manager (-m): %s
	+ before (-t): %s
	+ interval: %s
	+ metrics_address: %s
	+ metrics_port: %s
`, defaultConfigFile, defaultDir, defaultServiceManager, defaultBefore,
		defaultInterval, defaultMetricsAddr, defaultMetricsPort),
	Run: genConfig,
}

func init() {
	RootCmd.AddCommand(genconfigCmd)
	genconfigCmd.Flags().BoolVar(&force, "force", false, "force overwriting existing configuration files")
}
