// Package cert contains certificate specifications and
// certificate-specific management.
package cert

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"

	"gopkg.in/yaml.v2"

	"github.com/cenkalti/backoff"
	"github.com/cloudflare/certmgr/metrics"
	"github.com/cloudflare/certmgr/svcmgr"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/transport"
	"github.com/cloudflare/cfssl/transport/core"
	log "github.com/sirupsen/logrus"
)

// These are defaults used for limiting the backoff logic for cfssl transport
const backoffMaxDelay = time.Minute * 2

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
	return spec.Path
}

// Paths returns the paths that this spec is responsible for on disk
func (spec *Spec) Paths() []string {
	x := []string{}
	if spec.CA.File != nil {
		x = append(x, spec.CA.File.Path)
	}
	if spec.Cert != nil {
		x = append(x, spec.Cert.Path)
		x = append(x, spec.Key.Path)
	}
	return x
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

// loadFromPath load and fill this spec from the given pathway
// If this invocation returns an error, the spec instance should be discarded
// and recreated.
func (spec *Spec) loadFromPath(path string) error {
	in, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	specStat, err := os.Stat(path)
	if err != nil {
		// Hit the race; we read the file but someone wiped it.
		return err
	}

	switch filepath.Ext(path) {
	case ".json":
		err = strictJSONUnmarshal(in, &spec)
	case ".yml", ".yaml":
		err = yaml.UnmarshalStrict(in, &spec)
	default:
		err = fmt.Errorf("unrecognised spec file format for %s", path)
	}

	if err == nil {
		spec.loadTime = specStat.ModTime()
		spec.Path = path
	}
	return err
}

// Load reads a spec from a JSON configuration file.
func Load(path, remote string, before time.Duration, defaultServiceManager string) (*Spec, error) {
	var spec = &Spec{
		Request: csr.New(),
	}
	spec.CA.Remote = remote
	err := spec.loadFromPath(path)
	if err != nil {
		return nil, err
	}

	if spec.CA.Remote == "" {
		return nil, errors.New("no remote specified in authority (either in the spec or in the certmgr config)")
	}

	if (spec.Cert == nil) != (spec.Key == nil) {
		return nil, errors.New("if either cert or key are defined, both fields must be defined as must request to successfully write the keypair to disk")
	}

	if spec.Cert == nil && spec.CA.File == nil {
		return nil, errors.New("spec doesn't define either a CA, or keypair to write to disk")
	}

	// ensure the spec doesn't point the CA/key/cert at the same files.  And yes, this is quadratic- it's limited to max 3 however.
	paths := spec.Paths()
	for idx := range paths {
		for subidx := range paths {
			if idx != subidx && paths[idx] == paths[subidx] {
				return nil, fmt.Errorf("spec path for PKI material to manage on disk isn't unique for cert/key/CA aren't unique for value %s", paths[idx])
			}
		}
	}

	identity, err := spec.identity()
	if err != nil {
		return nil, err
	}
	spec.tr, err = transport.New(before, identity)
	if err != nil {
		return nil, err
	}

	// if no service manager was explicitly defined, use default if
	// no action/service is defined; else use the default.
	// If the default is not a dummy, it'll throw an error- which is desired
	// since that means the spec has a broken notification definition.
	if spec.ServiceManagerName == "" {
		spec.ServiceManagerName = defaultServiceManager
		if spec.Action == "" && spec.Service == "" {
			log.Warningf("spec %s defines no action, thus cannot not be notified of PKI changes", path)
			spec.ServiceManagerName = "dummy"
		}
	}

	spec.serviceManager, err = svcmgr.New(spec.ServiceManagerName, spec.Action, spec.Service)
	if err != nil {
		return nil, errors.WithMessagef(err, "while parsing spec")
	}

	metrics.SpecExpiresBeforeThreshold.WithLabelValues(spec.Path).Set(float64(before.Seconds()))
	return spec, nil
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
		return errors.New("unable to pem decode private key on disk")
	}

	var algDisk string
	var sizeDisk int
	privKey, err := x509.ParsePKCS1PrivateKey(pemKey.Bytes)
	if err != nil {
		privKey, err := x509.ParseECPrivateKey(pemKey.Bytes)
		if err != nil {
			// If we get here, then invalid key type
			return errors.New("unable to parse private key algorithm from disk")
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
		return fmt.Errorf("disk alg is %s but spec alg is %s", algDisk, algSpec)
	}

	if sizeDisk != sizeSpec {
		return fmt.Errorf("disk key size is %d but spec key size is %d", sizeDisk, sizeSpec)
	}

	// confirm that pkix is the same.  This catches things like OU being changed; these are slices
	// of slices and there isn't a usable equality check, thus the .String() usage.
	if csrRequest.Name().String() != cert.Subject.String() {
		return fmt.Errorf("subject has changed: was %s, now is %s", cert.Subject, csrRequest.Name())
	}

	if !hostnamesMatchesCertificate(csrRequest.Hosts, cert) {
		return errors.New("DNS names in cert on disk don't match with hostnames in spec")
	}

	// Check if cert and key are valid pair
	tlsCert, err := tls.X509KeyPair(encodeCertificateToPEM(cert), keyData)
	if err != nil || tlsCert.Leaf != nil {
		return fmt.Errorf("certificate and key on disk are not valid keypair: %s", err)
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

// checkDiskCertKey performs sanity checks against the cert/key read from disk, identifying
// if it's valid and still usable.
func (spec *Spec) checkDiskCertKey(ca *x509.Certificate) error {
	existingCert, err := spec.Cert.ReadCertificate()
	if err != nil {
		log.Debugf("spec %s: cert failed to be read: %s", spec, err)
		return err
	}
	err = spec.Cert.CheckPermissions()
	if err != nil {
		return errors.WithMessage(err, "cert requires regeneration due to permissions")
	}

	// update our internal time tracking while we're in here; even if immediately discard it,
	// keeping it accurate to when we last saw it is desirable for metrics.
	spec.updateCertExpiry(existingCert.NotAfter)

	keyData, err := spec.Key.ReadFile()
	if err != nil {
		log.Debugf("spec %s: key failed to be read: %s", spec, err)
		return err
	}

	err = spec.Key.CheckPermissions()
	if err != nil {
		return errors.WithMessage(err, "key requires regeneration due to permissions")
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
	now := time.Now()
	if now.After(existingCert.NotAfter) {
		return fmt.Errorf("certificate already expired at %s", existingCert.NotAfter)
	}
	now = now.Add(spec.tr.Before)
	if now.After(existingCert.NotAfter) {
		return fmt.Errorf("certificate is within the renewal threshold of %s: %s", spec.tr.Before, existingCert.NotAfter)
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

	currentCA, err = spec.CA.getRemoteCert()
	if err != nil {
		metrics.SpecRequestFailureCount.WithLabelValues(spec.Path).Inc()
		return errors.WithMessage(err, "failed getting remote")
	}

	if spec.renewalForced {
		updateReason = "key"
		err = errors.New("regeneration was forced")
	} else {

		if spec.CA.File != nil {
			var existingCA *x509.Certificate
			existingCA, err = spec.CA.File.ReadCertificate()
			if err != nil {
				err = errors.WithMessagef(err, "CA on disk is unusable")
				updateReason = "CA"
			} else {
				spec.updateCAExpiry(existingCA.NotAfter)

				err = spec.CA.File.CheckPermissions()
				if err != nil {
					err = errors.WithMessage(err, "CA permissions have changed")
					updateReason = "CA"
				} else if !existingCA.Equal(currentCA) {
					err = errors.New("on disk CA is no longer equal to new CA")
					updateReason = "CA"
				}
			}
		}

		if updateReason == "" && spec.Cert != nil {
			err = spec.checkDiskCertKey(currentCA)
			if err != nil {
				err = errors.WithMessagef(err, "on disk PKI failed validation")
				updateReason = "key"
			}
		}
	}

	if updateReason == "" {
		log.Debugf("spec %s: still up to date", spec)
		return nil
	}

	log.Infof("spec %s: renewal is needed due to: %s", spec, err)

	var pair *tls.Certificate
	if spec.Cert != nil {
		pair, err = spec.fetchNewKeyPair()
		if err != nil {
			return errors.WithMessagef(err, "failed to fetch new certificate pair")
		}
	}

	err = spec.writePKIToDisk(currentCA, pair)
	if err != nil {
		return err
	}

	if enableActions {
		err = spec.takeAction(updateReason)
		if err != nil {
			// Even though there was an error managing the service
			// associated with the certificate, the certificate has been
			// renewed.
			log.Errorf("spec %s: renewed on disk but failed taking action: %s", spec, err)
			return nil
		}
		log.Infof("spec %s: action successfully executed", spec)
	} else {
		log.Infof("skipping actions for %s due to calling mode", spec)
	}

	log.Info("manager: certificate successfully processed")

	return nil
}

// takeAction execute the configured svcmgr Action for this spec
func (spec *Spec) takeAction(changeType string) error {
	log.Debugf("spec %s: taking action due to %s", spec, changeType)
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

// writePKIToDisk writes the given PKI materials to disk, returning errors if anything occurs.
// CA must always be passed, but is optionally written if the spec defines an on disk CA.
// keypair can be nil if the spec does not write a cert/key- if it's just used for tracking the CA.
func (spec *Spec) writePKIToDisk(ca *x509.Certificate, keyPair *tls.Certificate) (err error) {

	metrics.SpecWriteCount.WithLabelValues(spec.Path).Inc()

	defer func() {
		if err != nil {
			metrics.SpecWriteFailureCount.WithLabelValues(spec.Path).Inc()
		} else {
			spec.renewalForced = false
		}
	}()

	if spec.CA.File != nil {
		err = spec.CA.File.WriteCertificate(ca)
		if err != nil {
			err = errors.WithMessagef(err, "failed writing CA to disk")
			return
		}
		spec.updateCAExpiry(ca.NotAfter)
	}

	if keyPair == nil {
		return nil
	}

	keyData, err := encodeKeyToPem(keyPair.PrivateKey)
	if err != nil {
		return
	}

	err = spec.Cert.WriteCertificate(keyPair.Leaf)
	if err != nil {
		err = errors.WithMessagef(err, "failed writing certificate to disk")
		return
	}
	err = spec.Key.WriteFile(keyData)

	if err != nil {
		err = errors.WithMessage(err, "failed writing key to disk")
		return
	}
	spec.updateCertExpiry(keyPair.Leaf.NotAfter)

	return
}

// fetchNewKeyPair request a fresh certificate/key from the transport, backing off as needed.
func (spec *Spec) fetchNewKeyPair() (*tls.Certificate, error) {
	metrics.SpecRefreshCount.WithLabelValues(spec.Path).Inc()

	// use exponential backoff rather than using cfssl's backoff implementation; that implementation
	// can back off up to an hour before returning control back to the invoker; that isn't
	// desirable.  If we can't get the requests in in a timely fahsion, we'll wake up and
	// revisit via our own scheduling.

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = backoffMaxDelay
	err := backoff.Retry(
		func() error {

			err := spec.tr.RefreshKeys()
			if err != nil {
				metrics.SpecRequestFailureCount.WithLabelValues(spec.Path).Inc()
				if isAuthError(err) {
					log.Errorf("spec %s: invalid auth key.  Giving up", spec)
					err = backoff.Permanent(errors.New("invalid auth key"))
				} else {
					log.Warningf("spec %s: failed fetching new cert: %s", spec, err)
				}
			}
			return err
		},
		b,
	)

	if err != nil {
		return nil, errors.WithMessage(err, "while fetching certificate/key")
	}

	pair, err := spec.tr.Provider.X509KeyPair()
	if err != nil {
		log.Errorf("spec %s: likely internal error, fetched new cert/key but couldn't create a keypair from it: %s", spec, err)
	}
	return &pair, err
}

func (spec *Spec) updateCertExpiry(notAfter time.Time) {
	spec.expiry.Cert = notAfter
	metrics.SpecExpires.WithLabelValues(spec.Path, "cert").Set(float64(notAfter.Unix()))
}
func (spec *Spec) updateCAExpiry(notAfter time.Time) {
	spec.expiry.CA = notAfter
	metrics.SpecExpires.WithLabelValues(spec.Path, "ca").Set(float64(notAfter.Unix()))
}

// WipeMetrics Wipes any metrics that may be recorded for this spec.
// In general this should be invoked only when a spec is being removed from tracking.
func (spec *Spec) WipeMetrics() {
	metrics.SpecRefreshCount.DeleteLabelValues(spec.Path)
	metrics.SpecCheckCount.DeleteLabelValues(spec.Path)
	metrics.SpecExpiresBeforeThreshold.DeleteLabelValues(spec.Path)
	metrics.SpecWriteCount.DeleteLabelValues(spec.Path)
	metrics.SpecWriteFailureCount.DeleteLabelValues(spec.Path)
	metrics.SpecRequestFailureCount.DeleteLabelValues(spec.Path)
	for _, t := range []string{"ca", "cert", "key"} {
		metrics.SpecExpires.DeleteLabelValues(spec.Path, t)
		metrics.ActionAttemptedCount.DeleteLabelValues(spec.Path, t)
		metrics.ActionFailedCount.DeleteLabelValues(spec.Path, t)
	}
}
