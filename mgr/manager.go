package mgr

import (
	"encoding/json"
	"errors"
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

// DefaultInterval is used if no interval is provided for a
// Manager. This defaults to one hour.
const DefaultInterval = time.Hour

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
	serviceManager svcmgr.Manager

	// Before is how long before the cert expires to start
	// attempting to renew it.
	Before string `json:"before" yaml:"before"`
	before time.Duration

	// Interval is how often to update the NextExpires metric.
	Interval string `json:"interval" yaml:"interval"`
	interval time.Duration

	// Certs contains the list of certificates to manage.
	Certs []*cert.Spec `json:",omitempty" yaml:",omitempty"`

	// renew is the queue used to manage certificates that need to
	// be renewed.
	renew chan *cert.Spec
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
	m.serviceManager, err = svcmgr.New(m.ServiceManager)
	if err != nil {
		return nil, err
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

// This defines the list of actions that the manager supports taking
// on a service whose certificate has been updated.
var validActions = map[string]bool{
	"restart": true,
	"reload":  true,
	"nop":     true,
}

// Load reads the certificate specs from the spec directory.
func (m *Manager) Load() error {
	if m.Certs != nil || len(m.Certs) > 0 {
		log.Debugf("manager: certificates already loaded")
		return nil
	}

	log.Info("manager: loading certificates from", m.Dir)
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

		log.Info("manager: loading spec from ", path)
		cert, err := cert.Load(path, m.DefaultRemote, m.before)
		if err != nil {
			return err
		}

		if cert.Action != "" {
			if !validActions[cert.Action] {
				return fmt.Errorf("manager: spec action '%s' is not supported", cert.Action)
			}

			if cert.Action != "nop" && cert.Service == "" {
				return errors.New("manager: spec defines an action but not service")
			}
		}

		m.Certs = append(m.Certs, cert)
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

	m.renew = make(chan *cert.Spec, len(m.Certs))
	return nil
}

// Queue adds the spec to the renewal queue if it isn't already
// queued.
func (m *Manager) Queue(spec *cert.Spec) {
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
func (m *Manager) MustCheckCerts(tolerance int) error {
	if tolerance < 1 {
		tolerance = 1
	}

	log.Infof("manager: ensuring all certificates exist and are ready (maximum %d tries)", tolerance)

	type queuedCert struct {
		cert     *cert.Spec
		errcount int
		err      error
	}

	var queue = make(chan *queuedCert, len(m.Certs))
	for i := range m.Certs {
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

func (m *Manager) renewCert(cert *cert.Spec) error {
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
		return cert.CA.Load()
	}
	stop := time.Now()

	cert.ResetBackoff()
	return fmt.Errorf("manager: failed to renew %s in %d attempts (in %0.0f seconds)", cert, maxAttempts, stop.Sub(start).Seconds())
}

// refreshKeys attempts to renew the certificate, perform any service
// management functions required, and update the metrics as needed.
func (m *Manager) refreshKeys(cert *cert.Spec) {
	err := m.renewCert(cert)
	if err != nil {
		m.renew <- cert
		log.Errorf("manager: failed to renew %s; requeuing cert", cert)
		return
	}

	metrics.QueueCount.Dec()
	switch cert.Action {
	case "restart":
		err = m.serviceManager.RestartService(cert.Service)
	case "reload":
		err = m.serviceManager.ReloadService(cert.Service)
	default:
		// Nothing to do here.
	}

	// Even though there was an error managing the service
	// associated with the certificate, the certificate has been
	// renewed.
	if err != nil {
		log.Errorf("manager: failed to %s service %s (err=%s)",
			cert.Action, cert.Service, err)
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
