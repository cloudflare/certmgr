package mgr

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/cloudflare/certmgr/cert"
	"github.com/cloudflare/certmgr/metrics"
	"github.com/cloudflare/certmgr/svcmgr"
	"github.com/cloudflare/cfssl/log"
	yaml "gopkg.in/yaml.v2"
)

// DefaultInterval is used if no interval is provided for a
// Manager. This defaults to one hour.
const DefaultInterval = time.Hour

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
	err := csm.CheckDiskPKI()
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

// CheckDiskPKI checks the PKI information on disk against cert spec and alerts upon differences
// Specifically, it checks that private key on disk matches spec algorithm & keysize,
// and certificate on disk matches CSR spec info
func (csm *CertServiceManager) CheckDiskPKI() error {
	certPath := csm.Spec.Cert.Path
	keyPath := csm.Spec.Key.Path
	specPath := csm.Spec.Path
	csrRequest := csm.Spec.Request

	// Read private key algorithm and keysize from disk, determine if RSA or ECDSA
	keyData, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return err
	}
	pemKey, _ := pem.Decode(keyData)
	if pemKey == nil {
		return errors.New("Unable to pem decode private key on disk")
	}

	var algDisk string
	var sizeDisk int
	privKey, err := x509.ParsePKCS1PrivateKey(pemKey.Bytes)
	if err != nil {
		privKey, err := x509.ParseECPrivateKey(pemKey.Bytes)
		if err != nil {
			// If we get here, then invalid key type
			return errors.New("manager: Unable to parse private key algorithm from disk")
		}
		// If we get here, then it's ECDSA
		algDisk = "ecdsa"
		sizeDisk = privKey.Curve.Params().BitSize
	} else {
		//If we get here, then it's RSA
		algDisk = "rsa"
		sizeDisk = privKey.N.BitLen()
	}

	// Check algorithm and keysize of private key on disk against what's defined in spec
	algSpec := csrRequest.KeyRequest.Algo()
	sizeSpec := csrRequest.KeyRequest.Size()

	if algDisk != algSpec {
		metrics.AlgorithmMismatchCount.WithLabelValues(specPath).Set(1)
		return fmt.Errorf("manager: disk alg is %s but spec alg is %s\n", algDisk, algSpec)
	} else {
		metrics.AlgorithmMismatchCount.WithLabelValues(specPath).Set(0)
	}

	if sizeDisk != sizeSpec {
		metrics.KeysizeMismatchCount.WithLabelValues(specPath).Set(1)
		return fmt.Errorf("manager: disk key size is %d but spec key size is %d\n", sizeDisk, sizeSpec)
	} else {
		metrics.KeysizeMismatchCount.WithLabelValues(specPath).Set(0)
	}

	// Check that certificate hostnames match spec hostnames
	certData, err := ioutil.ReadFile(certPath)
	if err != nil {
		return err
	}
	p, _ := pem.Decode(certData)
	if p == nil {
		return errors.New("Unable to pem decode certificate on disk")
	}
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return err
	}
	if !hostnamesEquals(csrRequest.Hosts, cert.DNSNames) {
		metrics.HostnameMismatchCount.WithLabelValues(specPath).Set(1)
		return errors.New("manager: DNS names in cert on disk don't match with hostnames in spec")
	} else {
		metrics.HostnameMismatchCount.WithLabelValues(specPath).Set(0)
	}

	// Check if cert and key are valid pair
	tlsCert, err := tls.X509KeyPair(certData, keyData)
	if err != nil || tlsCert.Leaf != nil {
		metrics.KeypairMismatchCount.WithLabelValues(specPath).Set(1)
		return fmt.Errorf("manager: Certificate and key on disk are not valid keypair: %s", err)
	} else {
		metrics.KeypairMismatchCount.WithLabelValues(specPath).Set(0)
	}
	return nil
}

// The Manager structure contains the certificates to be managed. A
// manager needs to be constructed with one of the New functions, and
// should not be constructed by hand.
type Manager struct {
	// Dir is the directory containing the certificate specs.
	Dir string `json:"certspecs" yaml:"certspecs"`

	// DefaultRemote is used as the remote CA server when no
	// remote is specified.
	DefaultRemote string `json:"default_remote" yaml:"default_remote"`

	// ServiceManager is the service manager used to restart a
	// service.
	ServiceManager string `json:"service_manager" yaml:"service_manager"`

	// Before is how long before the cert expires to start
	// attempting to renew it.
	Before string `json:"before" yaml:"before"`
	before time.Duration

	// Interval is how often to update the NextExpires metric.
	Interval string `json:"interval" yaml:"interval"`
	interval time.Duration

	// Certs contains the list of certificates to manage.
	Certs []*CertServiceManager `json:",omitempty" yaml:",omitempty"`
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
	if in[0] == '{' {
		err = json.Unmarshal(in, &m)
	} else {
		err = yaml.Unmarshal(in, &m)
	}
	if err != nil {
		return nil, err
	}

	return setup(m)
}

// New constructs a new Manager from parameters. It is intended to be
// used in conjunction with command line flags.
func New(dir, remote, svcmgr, before, interval string) (*Manager, error) {
	if dir == "" {
		return nil, fmt.Errorf("manager: invalid manager configuration (missing spec dir)")
	}

	if svcmgr == "" {
		return nil, fmt.Errorf("manager: invalid manager configuration (missing service manager)")
	}

	if before == "" {
		return nil, fmt.Errorf("manager: invalid manager configuration (missing before)")
	}

	m := &Manager{
		Dir:            dir,
		DefaultRemote:  remote,
		ServiceManager: svcmgr,
		Before:         before,
		Interval:       interval,
	}

	return setup(m)
}

// setup provides the common final setup work that needs to be done
// for a Manager to be ready.
func setup(m *Manager) (*Manager, error) {
	var err error

	m.Dir = filepath.Clean(m.Dir)

	if m.ServiceManager == "" {
		m.ServiceManager = "dummy"
	}

	m.before, err = time.ParseDuration(m.Before)
	if err != nil {
		return nil, err
	}

	if m.Interval == "" {
		m.interval = DefaultInterval
	} else {
		m.interval, err = time.ParseDuration(m.Interval)
		if err != nil {
			return nil, err
		}
	}
	return m, nil
}

var validExtensions = map[string]bool{
	".json": true,
	".yaml": true,
	".yml":  true,
}

// Compare if hostnames in certificate and spec are equal
func hostnamesEquals(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sort.Strings(a)
	sort.Strings(b)
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// Load reads the certificate specs from the spec directory.
func (m *Manager) Load(forced bool) error {
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
		cert, err := cert.Load(path, m.DefaultRemote, m.before)
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
		}
		if err != nil {
			return err
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
func (m *Manager) Server() {
	// NB: this loop could be more intelligent; for example,
	// updating the next expiration independently of checking
	// certificates.

	metrics.ManagerInterval.WithLabelValues(m.Dir, m.Interval).Set(1)

	m.CheckCerts()

	for {
		<-time.After(m.interval)

		for i := range m.Certs {
			spec := m.Certs[i].Spec
			if spec.IsChangedOnDisk(spec.Key.Path) || spec.IsChangedOnDisk(spec.Cert.Path) {
				err := m.Load(true)
				if err != nil {
					metrics.ActionFailure.WithLabelValues(spec.Path, "load").Inc()
					log.Debugf("manager: load: %s", err.Error())
				}
			}
		}

		m.CheckCerts()
	}
}
