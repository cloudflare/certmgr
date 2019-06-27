// Package cert contains certificate specifications and
// certificate-specific management.
package cert

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
	"strings"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/cloudflare/certmgr/metrics"
	"github.com/cloudflare/certmgr/svcmgr"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/transport"
	"github.com/cloudflare/cfssl/transport/core"
)

// A Spec contains information needed to monitor and renew a
// certificate.
type Spec struct {

	// This defines the service manager to use.  This should be defined
	// globally rather than per cert- it's allowed here to allow cert
	// definitions to use a servicemanager of 'command' to allow freeform
	// invocations.
	ServiceManagerName string `json:"svcmgr" yaml:"svcmgr"`

	serviceManager svcmgr.Manager

	// The service is the service that uses this certificate. If
	// this field is not empty, the action below will be applied
	// to this service upon certificate renewal. It can also be
	// used to describe what this certificate is for.
	Service string `json:"service" yaml:"service"`

	// Action is one of empty, "nop", "reload", or "restart" (see
	// the svcmgr package for details).
	Action string `json:"action" yaml:"action"`

	// Request contains the CSR metadata needed to request a
	// certificate.
	Request *csr.CertificateRequest `json:"request" yaml:"request"`

	// Key contains the file metadata for the private key.
	Key *File `json:"private_key" yaml:"private_key"`

	// Cert contains the file metadata for the certificate.
	Cert *CertificateFile `json:"certificate" yaml:"certificate"`

	// CA specifies the certificate authority that should be used.
	CA CA `json:"authority" yaml:"authority"`

	// Path points to the on-disk location of the certificate
	// spec.
	Path string

	tr *transport.Transport

	// used for tracking when the spec was read
	loadTime time.Time

	expiry struct {
		CA   time.Time
		Cert time.Time
	}

	// internal flag to track if we must force renewal irregardless of
	// validity or lifespan checks.
	renewalForced bool
}

func (spec *Spec) String() string {
	extra := displayName(spec.Request.Name())
	if extra == "" {
		extra = spec.Service
	}

	if extra == "" {
		extra = spec.Cert.Path
	}
	if extra != "" {
		return fmt.Sprintf("%s: %s", spec.Cert.Path, extra)
	}

	return spec.Cert.Path
}

// Identity creates a transport package identity for the certificate.
func (spec *Spec) identity() (*core.Identity, error) {
	ident := &core.Identity{
		Request: spec.Request,
		Roots: []*core.Root{
			&core.Root{
				Type: "system",
			},
			&core.Root{
				Type: "cfssl",
				Metadata: map[string]string{
					"host":          spec.CA.Remote,
					"profile":       spec.CA.Profile,
					"label":         spec.CA.Label,
					"tls-remote-ca": spec.CA.RootCACert,
				},
			},
		},
		Profiles: map[string]map[string]string{
			"cfssl": map[string]string{
				"remote":        spec.CA.Remote,
				"profile":       spec.CA.Profile,
				"label":         spec.CA.Label,
				"tls-remote-ca": spec.CA.RootCACert,
			},
		},
	}

	authkey := spec.CA.AuthKey
	if spec.CA.AuthKeyFile != "" {
		log.Debugf("loading auth_key_file %v", spec.CA.AuthKeyFile)
		content, err := ioutil.ReadFile(spec.CA.AuthKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed reading auth_key_file %v: %v", spec.CA.AuthKeyFile, err)
		}
		authkey = strings.TrimSpace(string(content))
	}
	if authkey != "" {
		ident.Profiles["cfssl"]["auth-type"] = "standard"
		ident.Profiles["cfssl"]["auth-key"] = authkey
	}

	return ident, nil
}

func newSpecFromPath(path string) (*Spec, error) {
	in, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	specStat, err := os.Stat(path)
	if err != nil {
		// Hit the race; we read the file but someone wiped it.
		return nil, err
	}
	var spec = &Spec{
		Request:  csr.New(),
		Path:     path,
		loadTime: specStat.ModTime(),
	}

	switch filepath.Ext(path) {
	case ".json":
		err = json.Unmarshal(in, &spec)
	case ".yml", ".yaml":
		err = yaml.UnmarshalStrict(in, &spec)
	default:
		err = fmt.Errorf("cert: unrecognised spec file format for %s", path)
	}

	return spec, err
}

// Load reads a spec from a JSON configuration file.
func Load(path, remote string, before time.Duration, defaultServiceManager string, strict bool) (*Spec, error) {
	spec, err := newSpecFromPath(path)
	if err != nil {
		return nil, err
	}

	if spec.CA.Remote == "" {
		spec.CA.Remote = remote
	}

	if spec.CA.Remote == "" {
		return nil, errors.New("cert: no remote specified in authority (either in the spec or in the certmgr config)")
	}

	identity, err := spec.identity()
	if err != nil {
		return nil, err
	}
	spec.tr, err = transport.New(before, identity)
	if err != nil {
		return nil, err
	}

	if spec.ServiceManagerName == "" {
		spec.ServiceManagerName = defaultServiceManager
	}

	manager, _ := svcmgr.New("dummy", "", "")
	if spec.Action != "" && spec.Action != "nop" {
		manager, err = svcmgr.New(spec.ServiceManagerName, spec.Action, spec.Service)
		if err != nil {
			return nil, err
		}
	}

	// If action is undefined and svcmgr isn't dummy, we will throw a warning due to likely undefined cert renewal behavior
	// We will refuse to even store/keep track of the cert if we're in strict mode
	if (spec.Action == "" || spec.Action == "nop") && (spec.ServiceManagerName != "" && spec.ServiceManagerName != "dummy") {
		log.Warningf("manager: No action defined for a non-dummy svcmgr in certificate spec. This can lead to undefined certificate renewal behavior.")
		if strict {
			return nil, fmt.Errorf("failed to load spec %s due to strict mode and non dummy service manager", path)
		}
	}
	spec.serviceManager = manager
	return spec, err
}

// refreshKeys will make sure the key pair in the Spec has loaded keys
// and has a valid certificate. It will handle any persistence, check
// that the certificate is valid (i.e. that its expiry date is within
// the Before date), and handle certificate reissuance as needed.
func (spec *Spec) refreshKeys() (*tls.Certificate, error) {
	if spec.tr == nil {
		panic("cert: cannot refresh keys because spec has an invalid transport")
	}

	err := spec.tr.RefreshKeys()
	if err != nil {
		return nil, err
	}
	// fetch the pair ourselves; persistent mode doesn't handle key algo/size changes, and
	// it allows for a window where the content has permissions not matching the spec's directive.
	pair, err := spec.tr.Provider.X509KeyPair()
	return &pair, err
}

// Lifespan returns a time.Duration for the certificate's validity.
func (spec *Spec) Lifespan() time.Duration {
	t := spec.expiry.CA
	if t.After(spec.expiry.Cert) {
		t = spec.expiry.Cert
	}
	return time.Now().Sub(t)
}

// HasChangedOnDisk returns (removed, changed, err) to indicate if the spec has changed
func (spec *Spec) HasChangedOnDisk() (bool, bool, error) {
	specStat, err := os.Stat(spec.Path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Debugf("spec %s was removed from on disk", spec)
			return true, false, nil
		}
		return false, false, err
	} else if specStat.ModTime().After(spec.loadTime) {
		log.Debugf("spec %s has changed on disk", spec)
		return false, true, nil
	}
	log.Debugf("spec %s hasn't changed on disk", spec)
	return false, false, nil
}

// checkDiskPKI checks the PKI information on disk against cert spec and alerts upon differences
// Specifically, it checks that private key on disk matches spec algorithm & keysize,
// and certificate on disk matches CSR spec info
func (spec *Spec) checkDiskPKI(cert *x509.Certificate, keyData []byte) error {
	csrRequest := spec.Request

	// Read private key algorithm and keysize from disk, determine if RSA or ECDSA
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
		return fmt.Errorf("manager: disk alg is %s but spec alg is %s", algDisk, algSpec)
	}

	if sizeDisk != sizeSpec {
		return fmt.Errorf("manager: disk key size is %d but spec key size is %d", sizeDisk, sizeSpec)
	}

	// confirm that pkix is the same.  This catches things like OU being changed; these are slices
	// of slices and there isn't a usable equality check, thus the .String() usage.
	if csrRequest.Name().String() != cert.Subject.String() {
		return fmt.Errorf("subject has changed: was %s, now is %s", cert.Subject, csrRequest.Name())
	}

	if !hostnamesEquals(csrRequest.Hosts, cert.DNSNames) {
		return errors.New("manager: DNS names in cert on disk don't match with hostnames in spec")
	}

	// Check if cert and key are valid pair
	tlsCert, err := tls.X509KeyPair(encodeCertificateToPEM(cert), keyData)
	if err != nil || tlsCert.Leaf != nil {
		return fmt.Errorf("manager: Certificate and key on disk are not valid keypair: %s", err)
	}
	return nil
}

// CertExpireTime returns the time at which this spec's Certificate is no
// longer valid.
func (spec *Spec) CertExpireTime() time.Time {
	return spec.expiry.Cert
}

// CAExpireTime returns the time at which this spec's CA is no
// longer valid.
func (spec *Spec) CAExpireTime() time.Time {
	return spec.expiry.CA
}

// ForceRenewal Reset the lifespan to force cfssl to regenerate
func (spec *Spec) ForceRenewal() {
	spec.renewalForced = true
}

// Backoff returns the backoff delay.
func (spec *Spec) Backoff() time.Duration {
	return spec.tr.Backoff.Duration()
}

// ResetBackoff resets the spec's backoff.
func (spec *Spec) ResetBackoff() {
	spec.tr.Backoff.Reset()
}

// checkDiskCertKey performs sanity checks against the cert/key read from disk, identifying
// if it's valid and still usable.
func (spec *Spec) checkDiskCertKey(ca *x509.Certificate) error {
	existingCert, err := spec.Cert.ReadCertificate()
	if err != nil {
		log.Debugf("spec %s: cert failed to be read: %s", spec, err)
		return err
	}
	// update our internal time tracking while we're in here; even if immediately discard it,
	// keeping it accurate to when we last saw it is desirable for metrics.
	spec.updateCertExpiry(existingCert.NotAfter)

	keyData, err := spec.Key.ReadFile()
	if err != nil {
		log.Debugf("spec %s: key failed to be read: %s", spec, err)
		return err
	}
	err = verifyCertChain(ca, existingCert)
	if err != nil {
		log.Debugf("spec %s: CA has changed, cert is no longer valid via it: %s", spec, err)
		return err
	}
	err = spec.checkDiskPKI(existingCert, keyData)
	if err != nil {
		return err
	}
	now := time.Now().Add(spec.tr.Before)
	if now.After(existingCert.NotAfter) {
		return fmt.Errorf("certificate already expired at %s", existingCert.NotAfter)
	}
	if existingCert.NotBefore.After(now) {
		// someone needs a better clock.
		return fmt.Errorf("certificate isn't yet valid: %s", existingCert.NotBefore)
	}
	return nil
}

// EnforcePKI processes a spec, updating content on disk, taking action as needed.
// Returns (TTL for PKI, error).  If an error occurs, the ttl is at best
// a hint to the invoker as to when the next refresh is required- that said
// the invoker should back off and try a refresh.
func (spec *Spec) EnforcePKI(enableActions bool) error {

	updateReason := ""
	var currentCA *x509.Certificate
	var err error

	metrics.SpecCheckCount.WithLabelValues(spec.Path).Inc()

	if spec.renewalForced {
		updateReason = "key"
	} else {
		currentCA, err = spec.CA.getRemoteCert()
		if err != nil {
			log.Errorf("spec %s: failed getting remote: %s", spec, err)
			metrics.SpecRequestFailureCount.WithLabelValues(spec.Path).Inc()
			return err
		}

		if spec.CA.File != nil {
			existingCA, err := spec.CA.File.ReadCertificate()
			if err != nil {
				log.Infof("spec %s: ca on disk needs regeneration: %s", spec, err)
				updateReason = "CA"
			} else {
				spec.updateCAExpiry(existingCA.NotAfter)
				if !existingCA.Equal(currentCA) {
					log.Debugf("spec %s: ca has changed", spec)
					updateReason = "CA"
				} else {
					log.Debugf("spec %s: ca is the same", spec)
				}
			}
		}

		if updateReason == "" {
			err := spec.checkDiskCertKey(currentCA)
			if err != nil {
				log.Infof("spec %s: forcing refresh due to %s", spec, err)
				updateReason = "key"
			}
		}
	}

	if updateReason == "" {
		log.Debugf("spec %s: still up to date", spec)
		return nil
	}

	err = spec.renewPKI(currentCA)
	if err != nil {
		log.Errorf("manager: failed to renew %s; requeuing cert", spec)
		return err
	}

	if enableActions {
		err = spec.TakeAction(updateReason)
	} else {
		log.Infof("skipping actions for %s due to calling mode", spec)
	}

	// Even though there was an error managing the service
	// associated with the certificate, the certificate has been
	// renewed.
	if err != nil {
		log.Errorf("manager: %s", err)
	}

	log.Info("manager: certificate successfully processed")

	return nil
}

// TakeAction execute the configured svcmgr Action for this spec
func (spec *Spec) TakeAction(changeType string) error {
	log.Infof("manager: executing configured action due to change type %s for %s", changeType, spec.Cert.Path)
	caPath := ""
	if spec.CA.File != nil {
		caPath = spec.CA.File.Path
	}
	metrics.ActionAttemptedCount.WithLabelValues(spec.Path, changeType).Inc()
	err := spec.serviceManager.TakeAction(changeType, spec.Path, caPath, spec.Cert.Path, spec.Key.Path)
	if err != nil {
		metrics.ActionFailedCount.WithLabelValues(spec.Path, changeType).Inc()
	}
	return err
}

// The maximum number of attempts before giving up.
const maxAttempts = 5

// renewPKI Try to update the on disk PKI content with a fresh CA/cert as needed
func (spec *Spec) renewPKI(ca *x509.Certificate) error {
	metrics.SpecRefreshCount.WithLabelValues(spec.Path).Inc()
	failed := true
	defer func() {
		if failed {
			metrics.SpecWriteFailureCount.WithLabelValues(spec.Path).Inc()
		}
	}()

	start := time.Now()
	for attempts := 0; attempts < maxAttempts; attempts++ {
		log.Infof("manager: processing certificate %s (attempt %d)", spec, attempts+1)
		pair, err := spec.refreshKeys()
		if err != nil {
			if isAuthError(err) {
				// Killing the server is really the
				// only valid option here; it will
				// force an investigation into why the
				// auth key is bad.
				log.Fatalf("invalid auth key for %s", spec)
			}
			backoff := spec.Backoff()
			log.Warningf("manager: failed to renew certificate (err=%s), backing off for %0.0f seconds", err, backoff.Seconds())
			metrics.SpecRequestFailureCount.WithLabelValues(spec.Path).Inc()
			time.Sleep(backoff)
			continue
		}
		keyData, err := encodeKeyToPem(pair.PrivateKey)
		if err != nil {
			return err
		}

		spec.ResetBackoff()
		err = spec.Cert.WriteCertificate(pair.Leaf)
		if err != nil {
			log.Errorf("spec %s: failed to write certificate to disk: %s", spec, err)
			return err
		}
		err = spec.Key.WriteFile(keyData)
		if err != nil {
			log.Errorf("spec %s: failed to write key to disk: %s", spec, err)
			return err
		}
		spec.updateCertExpiry(pair.Leaf.NotAfter)
		if spec.CA.File != nil {
			err = spec.CA.File.WriteCertificate(ca)
			if err != nil {
				return err
			}
		}
		spec.updateCAExpiry(ca.NotAfter)
		failed = false
		return nil
	}
	stop := time.Now()

	spec.ResetBackoff()
	spec.renewalForced = false
	return fmt.Errorf("manager: failed to renew %s in %d attempts (in %0.0f seconds)", spec, maxAttempts, stop.Sub(start).Seconds())
}

func (spec *Spec) updateCertExpiry(notAfter time.Time) {
	spec.expiry.Cert = notAfter
	metrics.SpecExpires.WithLabelValues(spec.Path, "cert").Set(float64(notAfter.Unix()))
}
func (spec *Spec) updateCAExpiry(notAfter time.Time) {
	spec.expiry.CA = notAfter
	metrics.SpecExpires.WithLabelValues(spec.Path, "cert").Set(float64(notAfter.Unix()))
}

// WipeMetrics Wipes any metrics that may be recorded for this spec.
// In general this should be invoked only when a spec is being removed from tracking.
func (spec *Spec) WipeMetrics() {
	metrics.SpecRefreshCount.DeleteLabelValues(spec.Path)
	metrics.SpecCheckCount.DeleteLabelValues(spec.Path)
	metrics.SpecWriteCount.DeleteLabelValues(spec.Path)
	metrics.SpecWriteFailureCount.DeleteLabelValues(spec.Path)
	metrics.SpecRequestFailureCount.DeleteLabelValues(spec.Path)
	for _, t := range []string{"ca", "cert", "key"} {
		metrics.SpecExpires.DeleteLabelValues(spec.Path, t)
		metrics.ActionAttemptedCount.DeleteLabelValues(spec.Path, t)
		metrics.ActionFailedCount.DeleteLabelValues(spec.Path, t)
	}
}
