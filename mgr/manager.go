package mgr

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/cloudflare/certmgr/cert"
	"github.com/cloudflare/certmgr/metrics"
	"github.com/cloudflare/cfssl/log"
	yaml "gopkg.in/yaml.v2"
)

// DefaultInterval is used if no duration is provided for a
// Manager. This defaults to one hour.
const DefaultInterval = time.Hour

// DefaultBefore is used if no duration is provided for a
// Manager. This defaults to 72 hours.
const DefaultBefore = time.Hour * 72

// The Manager structure contains the certificates to be managed. A
// manager needs to be constructed with one of the New functions, and
// should not be constructed by hand.
type Manager struct {
	// Dir is the directory containing the certificate specs.
	Dir string `yaml:"certspecs"`

	// DefaultRemote is used as the remote CA server when no
	// remote is specified.
	DefaultRemote string `yaml:"default_remote"`

	// ServiceManager is the service manager used to restart a
	// service.
	ServiceManager string `yaml:"service_manager"`

	// Before is how long before the cert expires to start
	// attempting to renew it.
	Before time.Duration `yaml:"before"`

	// Interval is how often to update the NextExpires metric.
	Interval time.Duration `yaml:"interval"`

	// Certs contains the list of certificates to manage.
	Certs []*cert.Spec `yaml:",omitempty"`
}

// UnmarshallYAML update a Manager instance via deserializing the given yaml
func (m *Manager) UnmarshallYAML(unmarshall func(interface{}) error) error {
	m = &Manager{
		Before:   DefaultBefore,
		Interval: DefaultInterval,
	}
	// use a cast to prevent unmarshall from going recursive against this
	// deserializer function.
	type plain Manager
	if err := unmarshall((*plain)(m)); err != nil {
		return err
	}
	return nil
}

// NewFromConfig loads a new Manager from a config file. This does not load the
// certificate specs; to do that, see Load(). If the file looks like a
// JSON file, it will attempt to load it as a JSON file; otherwise, it
// assumes that it is a YAML file.
func NewFromConfig(configPath string) (*Manager, error) {
	log.Info("manager: loading from configuration file")
	in, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var m = &Manager{}
	err = yaml.UnmarshalStrict(in, &m)
	if err != nil {
		err = m.validate()
	}
	return m, err
}

// New constructs a new Manager from parameters. It is intended to be
// used in conjunction with command line flags.
func New(dir string, remote string, svcmgr string, before time.Duration, interval time.Duration) (*Manager, error) {
	m := &Manager{
		Dir:            dir,
		DefaultRemote:  remote,
		ServiceManager: svcmgr,
		Before:         before,
		Interval:       interval,
	}

	return m, m.validate()
}

// setup provides the common final setup work that needs to be done
// for a Manager to be ready.
func (m *Manager) validate() error {
	if m.Dir == "" {
		return fmt.Errorf("manager: invalid manager configuration (missing spec dir)")
	}
	m.Dir = filepath.Clean(m.Dir)

	if m.ServiceManager == "" {
		m.ServiceManager = "dummy"
	}

	return nil
}

var validExtensions = map[string]bool{
	".json": true,
	".yaml": true,
	".yml":  true,
}

func (m *Manager) loadSpec(path string, strict bool) (*cert.Spec, error) {
	log.Infof("manager: loading spec from %s", path)
	spec, err := cert.Load(path, m.DefaultRemote, m.Before, m.ServiceManager, strict)
	if err == nil {
		log.Debugf("manager: successfully loaded spec from %s", path)
	} else {
		log.Errorf("managed: failed loading spec from %s: %s", path, err)
	}
	return spec, err
}

// Load reads the certificate specs from the spec directory.
func (m *Manager) Load(forced, strict bool) error {
	if (m.Certs != nil || len(m.Certs) > 0) && !forced {
		log.Debugf("manager: certificates already loaded")
		return nil
	}

	if forced {
		m.Certs = nil
	}

	log.Info("manager: loading certificates from ", m.Dir)
	walker := func(path string, info os.FileInfo, err error) error {
		if info == nil {
			return err
		}

		if info.IsDir() {
			if path == m.Dir {
				return nil
			}
			return filepath.SkipDir
		}

		ext := filepath.Ext(path)
		if !validExtensions[ext] {
			return nil
		}

		spec, err := m.loadSpec(path, strict)
		if err != nil {
			log.Errorf("stopping directory scan due to %s", err)
			return err
		}

		m.Certs = append(m.Certs, spec)
		metrics.SpecWatchCount.WithLabelValues(spec.Path, spec.ServiceManagerName, spec.Action, spec.CA.Label).Inc()
		return nil
	}

	err := filepath.Walk(m.Dir, walker)
	if err != nil {
		return err
	}

	if len(m.Certs) == 0 {
		log.Warning("manager: no certificate specs found")
	}

	log.Infof("manager: watching %d certificates", len(m.Certs))
	return nil
}

// CheckCerts verifies that certificates and keys are present, and
// refreshes anything needed, while updating the bookkeeping for when
// next to wake up.
func (m *Manager) CheckCerts() {
	log.Info("manager: checking certificates")
	for _, cert := range m.Certs {
		log.Debugf("manager: checking %s", cert)
		err := cert.EnforcePKI(true)
		if err != nil {
			log.Errorf("Failed processing %s due to %s", cert, err)
		}
	}
	log.Info("manager: finished checking certificates")
}

// Server runs the Manager server.
func (m *Manager) Server(strict bool) {
	// NB: this loop could be more intelligent; for example,
	// updating the next expiration independently of checking
	// certificates.

	metrics.ManagerInterval.WithLabelValues(m.Dir).Set(m.Interval.Seconds())

	m.CheckCerts()

	for {
		<-time.After(m.Interval)

		for idx, spec := range m.Certs {
			removed, changed, err := spec.HasChangedOnDisk()
			if err != nil {
				log.Errorf("failed checking spec on disk status for %s: %s", spec, err)
				continue
			}
			if removed {
				log.Warningf("spec %s was removed, certmgr requires a restart", spec)
				continue
			}
			if changed {
				newSpec, err := m.loadSpec(spec.Path, strict)
				if err != nil {
					log.Errorf("failed to reload spec %s due to %s. Continuing to use old spec.", spec, err)
					continue
				}
				log.Infof("reloaded spec %s due to detected changes", spec)
				m.Certs[idx] = newSpec
			}
		}

		m.CheckCerts()
	}
}
