package mgr

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/cloudflare/certmgr/cert"
	"github.com/cloudflare/certmgr/metrics"
	"github.com/cloudflare/certmgr/svcmgr"
	"github.com/cloudflare/cfssl/log"
	yaml "gopkg.in/yaml.v2"
)

// DefaultInterval is used if no duration is provided for a
// Manager. This defaults to one hour.
const DefaultInterval = time.Hour

// DefaultBefore is used if no duration is provided for a
// Manager. This defaults to 72 hours.
const DefaultBefore = time.Hour * 72

// This exists purely so we can bind custom svcmgr's per cert; this is primarily
// used for 'command' svcmgr's that don't follow the norm.
type CertServiceManager struct {
	*cert.Spec
	serviceManager svcmgr.Manager
}

func (csm *CertServiceManager) String() string {
	return fmt.Sprintf("spec: %s", csm.Spec.Path)
}

// Process a spec updating content on disk, taking action as needed.
// Returns (TTL for PKI, error).  If an error occurs, the ttl is at best
// a hint to the invoker as to when the next refresh is required- that said
// the invoker should back off and try a refresh.
func (csm *CertServiceManager) EnforcePKI(enable_actions bool) (time.Duration, error) {
	err := csm.Spec.CheckDiskPKI()
	if err != nil {
		log.Debugf("manager: %s, checkdiskpki: %s.  Forcing refresh.", csm, err.Error())
		csm.ResetLifespan()
	}

	if err = csm.CheckCA(); err != nil {
		log.Errorf("manager: the CA for %s has changed, but the service couldn't be notified of the change", csm)
	}

	lifespan := time.Duration(0)
	if !csm.Ready() {
		log.Debugf("manager: %s isn't ready", csm)
	} else {
		log.Debugf("manager: %s checking lifespan", csm)
		lifespan = csm.Lifespan()
	}
	log.Debugf("manager: %s has lifespan %s", csm, lifespan)
	if lifespan <= 0 {
		err := csm.RenewPKI()
		if err != nil {
			log.Errorf("manager: failed to renew %s; requeuing cert", csm)
			return 0, err
		}

		log.Debug("taking action due to key refresh")
		if enable_actions {
			err = csm.TakeAction("key")
		} else {
			log.Infof("skipping actions for %s due to calling mode", csm)
		}

		// Even though there was an error managing the service
		// associated with the certificate, the certificate has been
		// renewed.
		if err != nil {
			metrics.ActionFailure.WithLabelValues(csm.Spec.Path, "key").Inc()
			log.Errorf("manager: %s", err)
		}

		log.Info("manager: certificate successfully processed")
	}
	metrics.Expires.WithLabelValues(csm.Spec.Path, "cert").Set(float64(csm.CertExpireTime().Unix()))

	return csm.Lifespan(), nil
}

func (csm *CertServiceManager) TakeAction(change_type string) error {
	log.Infof("manager: executing configured action due to change type %s for %s", change_type, csm.Cert.Path)
	ca_path := ""
	if csm.CA.File != nil {
		ca_path = csm.CA.File.Path
	}
	cert_path := csm.Cert.Path
	key_path := csm.Key.Path
	metrics.ActionCount.WithLabelValues(csm.Cert.Path, change_type).Inc()
	return csm.serviceManager.TakeAction(change_type, csm.Path, ca_path, cert_path, key_path)
}

// The maximum number of attempts before giving up.
const maxAttempts = 5

func (cert *CertServiceManager) RenewPKI() error {
	start := time.Now()
	for attempts := 0; attempts < maxAttempts; attempts++ {
		log.Infof("manager: processing certificate %s (attempt %d)", cert, attempts+1)
		err := cert.RefreshKeys()
		if err != nil {
			if isAuthError(err) {
				// Killing the server is really the
				// only valid option here; it will
				// force an investigation into why the
				// auth key is bad.
				log.Fatalf("invalid auth key for %s", cert)
			}
			backoff := cert.Backoff()
			log.Warningf("manager: failed to renew certificate (err=%s), backing off for %0.0f seconds", err, backoff.Seconds())
			metrics.FailureCount.WithLabelValues(cert.Spec.Path).Inc()
			time.Sleep(backoff)
			continue
		}

		cert.ResetBackoff()
		return nil
	}
	stop := time.Now()

	cert.ResetBackoff()
	return fmt.Errorf("manager: failed to renew %s in %d attempts (in %0.0f seconds)", cert, maxAttempts, stop.Sub(start).Seconds())
}

// CheckCA checks the CA on the certificate and restarts the service
// if needed.
func (spec *CertServiceManager) CheckCA() error {
	var err error
	var changed bool
	if changed, err = spec.CA.Refresh(); err != nil {
		metrics.ActionFailure.WithLabelValues(spec.Spec.Path, "CA").Inc()
		return err
	} else if changed {
		metrics.Expires.WithLabelValues(spec.Spec.Path, "ca").Set(float64(spec.CAExpireTime().Unix()))
		log.Debug("taking action due to CA refresh")
		err := spec.TakeAction("CA")

		if err != nil {
			metrics.ActionFailure.WithLabelValues(spec.Spec.Path, "CA").Inc()
			log.Errorf("manager: %s", err)
		}
	}
	metrics.Expires.WithLabelValues(spec.Spec.Path, "ca").Set(float64(spec.CAExpireTime().Unix()))
	return err
}

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
	Certs []*CertServiceManager `yaml:",omitempty"`
}

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

// Load reads the certificate specs from the spec directory.
func (m *Manager) Load(forced, strict bool) error {
	if (m.Certs != nil || len(m.Certs) > 0) && !forced {
		log.Debugf("manager: certificates already loaded")
		return nil
	}

	if forced {
		m.Certs = nil
	}

	dummyMgr, _ := svcmgr.New("dummy", "", "")

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

		log.Info("manager: loading spec from ", path)
		cert, err := cert.Load(path, m.DefaultRemote, m.Before)
		if err != nil {
			return err
		}

		s := cert.ServiceManager
		if s == "" {
			s = m.ServiceManager
		}
		manager := dummyMgr
		if cert.Action != "" && cert.Action != "nop" {
			manager, err = svcmgr.New(s, cert.Action, cert.Service)
			if err != nil {
				return err
			}
		}
		// If action is undefined and svcmgr isn't dummy, we will throw a warning due to likely undefined cert renewal behavior
		// We will refuse to even store/keep track of the cert if we're in strict mode
		if (cert.Action == "" || cert.Action == "nop") && s != "dummy" {
			log.Warningf("manager: No action defined for a non-dummy svcmgr in certificate spec. This can lead to undefined certificate renewal behavior.")
			if strict {
				return nil
			}
		}
		m.Certs = append(m.Certs, &CertServiceManager{cert, manager})
		metrics.SpecWatchCount.WithLabelValues(cert.Path, s, cert.Action, cert.CA.Label).Inc()
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
		_, err := cert.EnforcePKI(true)
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

		for _, spec := range m.Certs {
			if spec.IsChangedOnDisk(spec.Key.Path) || spec.IsChangedOnDisk(spec.Cert.Path) {
				err := m.Load(true, strict)
				if err != nil {
					metrics.ActionFailure.WithLabelValues(spec.Path, "load").Inc()
					log.Debugf("manager: load: %s", err.Error())
				}
			}
		}

		m.CheckCerts()
	}
}
