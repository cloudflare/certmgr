package mgr

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cloudflare/certmgr/cert"
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

// MgrSpecOptions is a compatibility shim for mapping old manager configurables into
// the common names used by SpecOptions.
type MgrSpecOptions struct {
	cert.ParsableSpecOptions

	// OldServiceManagerField is the old yaml configurable name used for this.
	OldServiceManagerField string `yaml:"service_manager"`

	// OldRemoteName is the old yaml configurable name used for this.
	OldRemoteField string `yaml:"default_remote"`
}

// FinalizeSpecOptionParsing should be invoked to transfer fields from old location names
// to new location names for compatibility.
func (m *MgrSpecOptions) FinalizeSpecOptionParsing() {
	if m.OldServiceManagerField != "" {
		log.Warning("certmgr manager configuration field `service_manager` is deprecated and will be removed; please use `svcmgr` instead")
		m.SpecOptions.ServiceManagerName = m.OldServiceManagerField
	}
	if m.OldRemoteField != "" {
		log.Warning("certmgr manager configuration field `default_remote` is deprecated and will be removed; please use `remote` instead")
		m.SpecOptions.Remote = m.OldRemoteField
	}
	m.ParsableSpecOptions.FinalizeSpecOptionParsing()
}

// The Manager structure contains the certificates to be managed. A
// manager needs to be constructed with one of the New functions, and
// should not be constructed by hand.
type Manager struct {
	MgrSpecOptions

	// Dir is the directory containing the certificate specs.
	Dir string `yaml:"certspecs"`

	// Certs contains the list of certificates to manage.
	Certs []*cert.Spec `yaml:",omitempty"`

	// isLoaded tracks if we've loaded from disk already
	isLoaded bool

	// managedPaths tracks the paths managed by specs.  This is used to prevent
	// multiple specs from managing the same path
	managedPaths map[string]*cert.Spec
}

// UnmarshalYAML update a Manager instance via deserializing the given yaml
func (m *Manager) UnmarshalYAML(unmarshal func(interface{}) error) error {
	m = &Manager{}

	// use a cast to prevent unmarshal from going recursive against this
	// deserializer function.
	type plain Manager
	if err := unmarshal((*plain)(m)); err != nil {
		return err
	}
	m.FinalizeSpecOptionParsing()
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
		return nil, err
	}

	m.managedPaths = make(map[string]*cert.Spec)
	return m, nil
}

// New constructs a new Manager from parameters. It is intended to be
// used in conjunction with command line flags.
func New(dir string, defaults *cert.SpecOptions) (*Manager, error) {
	if dir == "" {
		return nil, errors.New("manager doesn't define a spec dir")
	}
	dir = filepath.Clean(dir)

	m := &Manager{
		Dir:          dir,
		managedPaths: make(map[string]*cert.Spec),
	}
	if defaults != nil {
		m.MgrSpecOptions.SpecOptions = *defaults
	}
	if m.MgrSpecOptions.Remote == "" {
		m.MgrSpecOptions.Remote = "dummy"
	}

	return m, nil
}

var validExtensions = map[string]bool{
	".json": true,
	".yaml": true,
	".yml":  true,
}

func (m *Manager) loadSpec(path string) (*cert.Spec, error) {
	log.Infof("manager: loading spec from %s", path)
	path = filepath.Clean(path)
	spec, err := cert.Load(path, &(m.MgrSpecOptions.SpecOptions))
	if err == nil {
		log.Debugf("manager: successfully loaded spec from %s with begin %v", path, spec.Before)
	} else {
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

// Server runs the Manager server.
func (m *Manager) Server(ctx context.Context) {
	var wg sync.WaitGroup
	defer wg.Wait()

	for _, spec := range m.Certs {
		wg.Add(1)
		go func(s *cert.Spec) {
			defer wg.Done()
			s.Run(ctx)
		}(spec)
	}
}
