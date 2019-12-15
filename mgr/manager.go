package mgr

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/cloudflare/certmgr/cert"
	"github.com/cloudflare/certmgr/metrics"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
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

	// isLoaded tracks if we've loaded from disk already
	isLoaded bool

	// managedPaths tracks the paths managed by specs.  This is used to prevent
	// multiple specs from managing the same path
	managedPaths map[string]*cert.Spec
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
	m.managedPaths = make(map[string]*cert.Spec)
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
		managedPaths:   make(map[string]*cert.Spec),
	}

	return m, m.validate()
}

// setup provides the common final setup work that needs to be done
// for a Manager to be ready.
func (m *Manager) validate() error {
	if m.Dir == "" {
		return errors.New("manager doesn't define a spec dir")
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

func (m *Manager) loadSpec(path string) (*cert.Spec, error) {
	log.Infof("manager: loading spec from %s", path)
	path = filepath.Clean(path)
	metrics.SpecLoadCount.WithLabelValues(path).Inc()
	spec, err := cert.Load(path, m.DefaultRemote, m.Before, m.ServiceManager)
	if err == nil {
		log.Debugf("manager: successfully loaded spec from %s", path)
	} else {
		metrics.SpecLoadFailureCount.WithLabelValues(path).Inc()
		log.Errorf("managed: failed loading spec from %s: %s", path, err)
	}
	return spec, err
}

// updateManagedPaths updates the internal bookkeeping of managed paths, rejecting
// the passed in spec if it wishes to manage a path already managed by another spec
// This invocation is transactional; the paths are added only if there is no conflict.
func (m *Manager) updateManagedPaths(oldSpec *cert.Spec, newSpec *cert.Spec) error {
	paths := newSpec.Paths()
	for idx := range paths {
		if preexisting, ok := m.managedPaths[paths[idx]]; ok && preexisting != oldSpec {
			return fmt.Errorf("pathway %s is already managed by spec %s", paths[idx], preexisting)
		}
	}

	if oldSpec != nil {
		for _, path := range oldSpec.Paths() {
			delete(m.managedPaths, path)
		}
	}

	for idx := range paths {
		m.managedPaths[paths[idx]] = newSpec
	}
	return nil
}

// Load reads the certificate specs from the spec directory.
func (m *Manager) Load() error {
	if m.isLoaded {
		return errors.New("manager is already loaded")
	}

	m.Certs = make([]*cert.Spec, 0)

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

		spec, err := m.loadSpec(path)
		if err != nil {
			log.Errorf("stopping directory scan due to %s", err)
			return err
		}

		err = m.updateManagedPaths(nil, spec)
		if err != nil {
			return errors.WithMessagef(err, "while loading spec %s", spec)
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

	m.isLoaded = true
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
func (m *Manager) Server(ctx context.Context) {

	metrics.ManagerInterval.WithLabelValues(m.Dir).Set(m.Interval.Seconds())

	m.CheckCerts()

	for {
		select {

		case <-time.After(m.Interval):
			m.warnIfSpecsHaveChanged()
			m.CheckCerts()

		case <-ctx.Done():
			m.shutdown()
			return
		}
	}
}

// shutdown shut's down the manager, including metric cleanup
func (m *Manager) shutdown() {
	for _, spec := range m.Certs {
		spec.WipeMetrics() // cleanup the metrics from the specs before we exit
	}
	metrics.ManagerInterval.DeleteLabelValues(m.Dir)
}

// reloadSpecsIfChanged checks spec's on disk to see if there has been changes, and reloads
// accordingly.  This behaviour should eventually be eliminated and require users to do an
// explicit sighup to reload configs, rather than this opportunistic (and potentially ill timed)
// approach.
func (m *Manager) warnIfSpecsHaveChanged() {
	for _, spec := range m.Certs {
		removed, changed, err := spec.HasChangedOnDisk()
		if err != nil {
			log.Errorf("failed checking spec on disk status for %s: %s", spec, err)
		} else if removed {
			log.Warningf("spec %s was removed, certmgr requires a reload for this to be effected", spec)
		} else if changed {
			log.Warningf("spec %s has changed, certmgr reload is required", spec)
		}
	}

}
