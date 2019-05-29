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
	"reflect"
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

func (csm *CertServiceManager) TakeAction(change_type string) error {
	log.Infof("manager: executing configured action due to change type %s for %s", change_type, csm.Cert.Path)
	ca_path := ""
	if csm.CA.File != nil {
		ca_path = csm.CA.File.Path
	}
	cert_path := csm.Cert.Path
	key_path := csm.Key.Path
	return csm.serviceManager.TakeAction(change_type, csm.Path, ca_path, cert_path, key_path)
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

	// renew is the queue used to manage certificates that need to
	// be renewed.
	renew chan *CertServiceManager
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

// CheckImpendingExpiry checks if a certificate will expire in <=24 hours and alerts on it
// TODO: HOW DO I TEST THIS???
func (m *Manager) CheckImpendingExpiry() error {
	if m.Certs == nil || len(m.Certs) == 0 {
		return nil
	}
	for i := range m.Certs {
		certPath := m.Certs[i].Spec.Cert.Path
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

		// Get expiry of cert on disk, alert on mismatch or if it's in <1 day
		expiryTime := cert.NotAfter
		diff := expiryTime.Sub(time.Now())
		if diff.Hours() <= 24 {
			fmt.Println("ALERT! CERTIFICATE ON DISK WITH EXPIRE IN <=24 HOURS")
			return errors.New("manager: Expiry will occur within day")
		}
	}
	return nil
}

// CheckDiskPKI checks the PKI information on disk against cert spec and alerts upon differences
// Specifically, it checks that private key on disk matches spec algorithm & keysize,
// and certificate  on disk matches CSR spec info
func (m *Manager) CheckDiskPKI() error {

	if m.Certs == nil || len(m.Certs) == 0 {
		return nil
	}

	// Iterate through certificates. Compare what's on disk to what's structurally stored
	for i := range m.Certs {
		csm := m.Certs[i]
		certPath := csm.Spec.Cert.Path
		keyPath := csm.Spec.Key.Path
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
			fmt.Printf("ALERT! ALGORITHM TYPES DON'T MATCH: disk alg is %s but spec alg is %s\n", algDisk, algSpec)
		}
		if sizeDisk != sizeSpec {
			fmt.Printf("ALERT! KEY SIZES DON'T MATCH: disk key size is %d but spec key size is %d\n", sizeDisk, sizeSpec)
		}

		// Check that certificate values match spec
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
		if !reflect.DeepEqual(csrRequest.Hosts, cert.DNSNames) {
			fmt.Println("ALERT: DNS NAMES OF CERT ON DISK DON'T MATCH UP WITH SPEC")
		}

		// Check if cert and key are valid pair
		tlsCert, err := tls.X509KeyPair(certData, keyData)
		if err != nil || tlsCert.Leaf != nil {
			fmt.Println("ALERT: CERTIFICATE AND PRIVATE KEY ON DISK ARE NOT A VALID KEYPAIR")
		}
	}
	return nil
}

// Load reads the certificate specs from the spec directory.
func (m *Manager) Load() error {
	if m.Certs != nil || len(m.Certs) > 0 {
		log.Debugf("manager: certificates already loaded")
		return nil
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
		metrics.WatchCount.Inc()
		return nil
	}

	err := filepath.Walk(m.Dir, walker)
	if err != nil {
		return err
	}

	if len(m.Certs) == 0 {
		return errors.New("manager: no certificate specs found")
	}

	log.Infof("manager: watching %d certificates", len(m.Certs))

	m.renew = make(chan *CertServiceManager, len(m.Certs))
	return nil
}

// CheckCA checks the CA on the certificate and restarts the service
// if needed.
func (m *Manager) CheckCA(spec *CertServiceManager) error {
	if changed, err := spec.CA.Refresh(); err != nil {
		return err
	} else if changed {
		log.Debug("taking action due to CA refresh")
		err := spec.TakeAction("CA")

		if err != nil {
			log.Errorf("manager: %s", err)
		}
		return err
	}
	return nil
}

// Queue adds the spec to the renewal queue if it isn't already
// queued.
func (m *Manager) Queue(spec *CertServiceManager) {
	if spec.IsQueued() {
		return
	}
	spec.Queue()
	m.renew <- spec
	metrics.QueueCount.Inc()
}

// CheckCerts verifies that certificates and keys are present, and
// queues any certificates that need to be renewed. It returns
// time.Duration indicating how long until the next certificate check
// should occur.
func (m *Manager) CheckCerts() {
	var next time.Duration

	log.Info("manager: checking certificates")
	for i := range m.Certs {
		if err := m.CheckCA(m.Certs[i]); err != nil {
			log.Errorf("manager: the CA for %s has changed, but the service couldn't be notified of the change", m.Certs[i])
		}

		if !m.Certs[i].Ready() {
			log.Infof("manager: queueing %s because it isn't ready", m.Certs[i])
			m.Queue(m.Certs[i])
			continue
		}

		lifespan := m.Certs[i].Lifespan()
		if lifespan <= 0 {
			log.Info("manager: queueing certificate with lifespan of ", lifespan.Hours(), " hours")
			m.Queue(m.Certs[i])
			continue
		}

		if next == 0 || next > lifespan {
			next = lifespan
		}
	}

	m.SetExpiresNext()
}

// CheckCertsSync acts like CheckCerts, except that it doesn't queue
// the certificates: it makes an initial synchronous attempt at
// ensuring that each certificate exists. If an error occurs, the
// certificate is added to the renewal queue. This is useful, for
// example, on program startup. It returns the number of certificates
// that were unable to be generated.
func (m *Manager) CheckCertsSync() int {
	var failed int

	log.Info("manager: checking certificates (sync)")
	for i := range m.Certs {
		if err := m.CheckCA(m.Certs[i]); err != nil {
			log.Errorf("manager: the CA for %s has changed, but the service couldn't be notified of the change", m.Certs[i])
		}

		if !m.Certs[i].Ready() && !m.Certs[i].IsQueued() {
			err := m.Certs[i].RefreshKeys()
			if err != nil {
				metrics.FailureCount.Inc()
				log.Warningf("manager: failed to refresh keys (err=%s); queueing", err)
				m.Queue(m.Certs[i])
				failed++
				continue
			}
		}

		if m.Certs[i].Lifespan() <= 0 {
			err := m.Certs[i].RefreshKeys()
			if err != nil {
				metrics.FailureCount.Inc()
				log.Warningf("manager: failed to refresh keys (err=%s); queueing", err)
				m.Queue(m.Certs[i])
				failed++
				continue
			}
		}
	}

	m.SetExpiresNext()
	return failed
}

// MustCheckCerts acts like CheckCerts, except it's synchronous and
// has a maxmimum number of failures that are tolerated. If tolerate
// is less than 1, it will be set to 1.
func (m *Manager) MustCheckCerts(tolerance int, enableActions bool, forceRegen bool) error {
	if tolerance < 1 {
		tolerance = 1
	}

	log.Infof("manager: ensuring all certificates exist and are ready (maximum %d tries)", tolerance)

	type queuedCert struct {
		cert     *CertServiceManager
		errcount int
		err      error
	}

	var queue = make(chan *queuedCert, len(m.Certs))
	for i := range m.Certs {
		if err := m.CheckCA(m.Certs[i]); err != nil {
			log.Errorf("manager: the CA for %s has changed, but the service couldn't be notified of the change", m.Certs[i])
		}

		if forceRegen {
			log.Debugf("manager: forcing regeneration of spec %s", m.Certs[i])
			m.Certs[i].ResetLifespan()
			queue <- &queuedCert{cert: m.Certs[i]}
			continue
		}
		if !m.Certs[i].Ready() && !m.Certs[i].IsQueued() {
			queue <- &queuedCert{cert: m.Certs[i]}
			continue
		}

		if m.Certs[i].Lifespan() <= 0 {
			queue <- &queuedCert{cert: m.Certs[i]}
			continue
		}
	}

	if len(queue) == 0 {
		log.Infof("manager: all certificates are up-to-date.")
		close(queue)
	}

	for cert := range queue {
		log.Infof("manager: processing certificate spec %s on attempt %d",
			cert.cert.Path, cert.errcount+1)
		if cert.errcount >= tolerance {
			if cert.err != nil {
				return cert.err
			}
			return fmt.Errorf("manager: failed to ensure certificate is present (spec=%s); no reason was given.", cert.cert.Path)
		}

		cert.err = cert.cert.RefreshKeys()
		if cert.err != nil {
			log.Errorf("manager: failed to process spec: %s; queueing for retry", cert.cert.Path)
			cert.errcount++
			queue <- cert
			continue
		}
		log.Infof("manager: certificate spec %s successfully processed", cert.cert.Path)
		if enableActions {
			log.Debug("taking action due to key refresh")
			err := cert.cert.TakeAction("key")

			// Even though there was an error managing the service
			// associated with the certificate, the certificate has been
			// renewed.
			if err != nil {
				log.Errorf("manager: %s", err)
			}
		}

		if len(queue) == 0 {
			log.Infof("manager: certificate queue is clear")
			close(queue)
			break
		}
	}

	return nil
}

// SetExpiresNext sets the next expiration metric.
func (m *Manager) SetExpiresNext() {
	var expires time.Time

	log.Debugf("manager: checking expiration on %d certificates", len(m.Certs))
	for i := range m.Certs {
		cert := m.Certs[i].Certificate()
		if cert == nil {
			log.Debugf("manager: spec has unloaded certificate (%s)", m.Certs[i])
			continue
		}

		log.Debugf("manager: %s expires at %s", m.Certs[i], cert.NotAfter)
		if expires.After(cert.NotAfter) || expires.IsZero() {
			expires = cert.NotAfter
		}
	}

	if expires.IsZero() {
		log.Debug("manager: all certificates are set to renew")
		metrics.ExpireNext.Set(0)
	} else {
		next := expires.Sub(time.Now())
		log.Debugf("manager: next certificate expires in %0.0f hours", next.Hours())
		metrics.ExpireNext.Set(next.Hours())
	}
}

// The maximum number of attempts before putting the cert back on the
// queue.
const maxAttempts = 5

func (m *Manager) renewCert(cert *CertServiceManager) error {
	start := time.Now()
	for attempts := 0; attempts < maxAttempts; attempts++ {
		log.Infof("manager: processing certificate spec %s (attempt %d)", cert, attempts+1)
		err := cert.RefreshKeys()
		if err != nil {
			if isAuthError(err) {
				// Killing the server is really the
				// only valid option here; it will
				// force an investigation into why the
				// auth key is bad.
				log.Fatalf("invalid auth key in certificate spec %s", cert.Path)
			}
			backoff := cert.Backoff()
			log.Warningf("manager: failed to renew certificate (err=%s), backing off for %0.0f seconds", err, backoff.Seconds())
			metrics.FailureCount.Inc()
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

// refreshKeys attempts to renew the certificate, perform any service
// management functions required, and update the metrics as needed.
func (m *Manager) refreshKeys(cert *CertServiceManager) {
	err := m.renewCert(cert)
	if err != nil {
		m.renew <- cert
		log.Errorf("manager: failed to renew %s; requeuing cert", cert)
		return
	}

	metrics.QueueCount.Dec()
	log.Debug("taking action due to key refresh")
	err = cert.TakeAction("key")

	// Even though there was an error managing the service
	// associated with the certificate, the certificate has been
	// renewed.
	if err != nil {
		log.Errorf("manager: %s", err)
	}

	cert.Dequeue()
	log.Info("manager: certificate successfully processed")

	m.SetExpiresNext()
}

// ProcessQueue retrieves certificates from the renewal queue and
// attempts to renew them. It is intended to be run as a goroutine.
func (m *Manager) ProcessQueue() {
	log.Info("manager: queue processor is ready")
	for {
		cert, ok := <-m.renew
		if !ok {
			return
		}

		go m.refreshKeys(cert)
	}
}

// Server runs the Manager server. If sync is true, the first pass
// will be synchronous. It will autostart the renewal queue.
func (m *Manager) Server(sync bool) {
	// NB: this loop could be more intelligent; for example,
	// updating the next expiration independently of checking
	// certificates.
	go m.ProcessQueue()

	if sync {
		failed := m.CheckCertsSync()
		if failed != 0 {
			log.Infof("manager: failed to provision %d certs (certs are queued)")
		}
	} else {
		m.CheckCerts()
	}

	for {
		<-time.After(m.interval)
		m.CheckCerts()
		m.SetExpiresNext()
	}
}
