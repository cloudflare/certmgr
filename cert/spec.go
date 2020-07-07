// Package cert contains certificate specifications and
// certificate-specific management.
package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/rand"
	"time"

	"github.com/pkg/errors"

	"github.com/cenkalti/backoff"
	"github.com/cloudflare/certmgr/cert/storage"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/transport"
	log "github.com/sirupsen/logrus"
)

// These are defaults used for limiting the backoff logic for cfssl transport
const backoffMaxDelay = time.Minute * 2

//
// DefaultInterval is used if no duration is provided for a
// Manager. This defaults to one hour.
const DefaultInterval = time.Hour

// DefaultBefore is used if no duration is provided for a
// Manager. This defaults to 72 hours.
const DefaultBefore = time.Hour * 72

// SpecOptions is a struct used for holding defaults used for instantiating a spec.
type SpecOptions struct {
	// Before is how long before the cert expires to start
	// attempting to renew it.  If unspecified, the manager default is used.
	Before time.Duration

	// Interval is how often to update the NextExpires metric.
	Interval time.Duration

	// IntervalSplay is a randomized Duration between 0 and IntervalSplay that is added to each interval
	// to distribute client load across time.  The bounding of a clients wake is [Interval, Interval + IntervalSplay]
	IntervalSplay time.Duration

	// InitialSplay is a randomized Duration between [0, InitialSplay] to sleep after the first PKI check.
	// This is Primarily useful to force an initial randomization if many nodes with certmgr are restarted all
	// at the same time.
	InitialSplay time.Duration

	// KeyUsages specifies what this key will be used for, so that certmgr can verify it is valid for that usage.
	// It is optional and by default we assume keys will be used for "TLS Web Server Authentication"
	KeyUsages []x509.ExtKeyUsage
}

// NewSpecOptions creates a new SpecOptions struct and populates it with defaults.
func NewSpecOptions() *SpecOptions {
	return &SpecOptions{
		Before:   DefaultBefore,
		Interval: DefaultInterval,
	}
}

// A Spec contains information needed to monitor and renew a
// certificate.
type Spec struct {
	SpecOptions

	// Name is the name to use for logs and metrics for this spec
	Name string

	// Authority holds the cfssl authority details.
	Authority *Authority
	// Request contains the CSR metadata needed to request a
	// certificate.
	Request *csr.CertificateRequest

	// Storage interface for loading/storing PKI materials
	Storage storage.PKIStorage

	// WakeCallbacks is list of callback's to invoke whenever the Spec wakes to do
	// enforcement checks.  Uses for this are fairly corner case- ReadSpecFile for example
	// uses this to register logging checks if the backing spec has been removed from disk.
	WakeCallbacks []func()

	tr *transport.Transport

	expiry struct {
		CA   time.Time
		Cert time.Time
	}
}

// NewSpec creates a Spec.
func NewSpec(name string, options *SpecOptions, authority *Authority, request *csr.CertificateRequest, storage storage.PKIStorage) (*Spec, error) {
	tr, err := authority.CreateTransport(options.Before, request)
	if err != nil {
		return nil, err
	}

	return &Spec{
		Name:        name,
		SpecOptions: *options,
		Authority:   authority,
		Request:     request,
		Storage:     storage,
		tr:          tr,
	}, nil
}

func (spec *Spec) String() string {
	return spec.Name
}

// Lifespan returns a time.Duration for the certificate's validity.
func (spec *Spec) Lifespan() time.Duration {
	t := spec.expiry.CA
	if t.After(spec.expiry.Cert) {
		t = spec.expiry.Cert
	}
	return time.Now().Sub(t)
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

func (spec *Spec) validateStoredPKI(currentCA *x509.Certificate) error {

	existingCA, keyPair, err := spec.Storage.Load()
	if err != nil {
		return errors.WithMessage(err, "stored PKI is invalid")
	}
	spec.updateCAExpiry(currentCA.NotAfter)

	if existingCA != nil {
		if !existingCA.Equal(currentCA) {
			return errors.New("stored CA is out of date with new CA")
		}
	}
	if !spec.Storage.WantsKeyPair() {
		// nothing further to check
		return nil
	}
	if keyPair.Leaf == nil {
		// tls.LoadX509KeyPair doesn't retain leaf, force the reparse
		leaf, err := x509.ParseCertificate(keyPair.Certificate[len(keyPair.Certificate)-1])
		if err != nil {
			return errors.WithMessage(err, "failed parsing stored certificate")
		}
		keyPair.Leaf = leaf
	}
	// update internal metrics
	spec.updateCertExpiry(keyPair.Leaf.NotAfter)

	err = CertificateChainVerify(currentCA, keyPair.Leaf, spec.KeyUsages)
	if err != nil {
		return errors.WithMessage(err, "stored cert failed CA check")
	}

	// confirm that pkix is the same.  This catches things like OU being changed; these are slices
	// of slices and there isn't a usable equality check, thus the .String() usage.
	if spec.Request.Name().String() != keyPair.Leaf.Subject.String() {
		return fmt.Errorf("spec subject has changed: was %s, now is %s", keyPair.Leaf.Subject, spec.Request.Name())
	}

	if !CertificateMatchesHostname(spec.Request.Hosts, keyPair.Leaf) {
		return errors.New("spec DNS name has changed")
	}

	// validate that the cert isn't expired and is still valid.
	now := time.Now()
	if now.After(keyPair.Leaf.NotAfter) {
		return fmt.Errorf("certificate already expired at %s", keyPair.Leaf.NotAfter)
	}
	now = now.Add(spec.tr.Before)
	if now.After(keyPair.Leaf.NotAfter) {
		return fmt.Errorf("certificate is within the renewal threshold of %s: %s", spec.tr.Before, keyPair.Leaf.NotAfter)
	}
	if keyPair.Leaf.NotBefore.After(now) {
		// someone needs a better clock.
		return fmt.Errorf("certificate isn't yet valid: %s", keyPair.Leaf.NotBefore)
	}
	return spec.validatePrivKey(keyPair.PrivateKey)
}

func (spec *Spec) validatePrivKey(privateKey interface{}) error {
	verify := func(algo string, size int) error {
		if spec.Request.KeyRequest.Algo() != algo {
			return fmt.Errorf("key algo is %s, must be %s", algo, spec.Request.KeyRequest.Algo())
		}
		if spec.Request.KeyRequest.Size() != size {
			return fmt.Errorf("key size is %d, must be %d", size, spec.Request.KeyRequest.Size())
		}
		return nil
	}

	switch key := privateKey.(type) {
	case (*rsa.PrivateKey):
		return verify("rsa", key.N.BitLen())
	case (*ecdsa.PrivateKey):
		return verify("ecdsa", key.Curve.Params().BitSize)
	}
	return fmt.Errorf("unsupported key algorithm: %T", privateKey)
}

// UpdateIfNeeded performs a refresh only if PKI is in need of a refresh (expired, new CA, etc)
func (spec *Spec) UpdateIfNeeded() error {
	ca, err := spec.getCurrentCA()
	if err != nil {
		return err
	}
	err = spec.validateStoredPKI(ca)
	if err == nil {
		log.Debugf("spec %s is still valid", spec)
		return nil
	}
	log.Infof("spec %s is needs refresh: %s", spec, err)
	return spec.doRefresh(ca)
}

// ForceUpdate forces a refresh of the PKI content
func (spec *Spec) ForceUpdate() error {
	ca, err := spec.getCurrentCA()
	if err != nil {
		return err
	}
	log.Infof("refresh was forced for %s", spec)
	return spec.doRefresh(ca)
}

func (spec *Spec) doRefresh(currentCA *x509.Certificate) error {
	var keyPair *tls.Certificate
	var err error

	log.Debugf("performing refresh for %s", spec)

	if spec.Storage.WantsKeyPair() {
		log.Debugf("spec %s: uses keyPairs, fetching", spec)
		keyPair, err = spec.fetchNewKeyPair()
		if err != nil {
			return errors.WithMessage(err, "while fetching new keyPair")
		}
	}
	log.Debugf("spec %s: storing content", spec)
	return errors.WithMessage(
		spec.writePKIToStorage(currentCA, keyPair),
		"storing PKI",
	)
}

func (spec *Spec) getCurrentCA() (*x509.Certificate, error) {
	ca, err := spec.Authority.getRemoteCert()
	err = errors.WithMessagef(err, "requested CA for spec %s", spec)
	if err != nil {
		SpecRequestFailureCount.WithLabelValues(spec.Name).Inc()
	}
	return ca, err
}

func (spec *Spec) writePKIToStorage(ca *x509.Certificate, keyPair *tls.Certificate) error {
	SpecWriteCount.WithLabelValues(spec.Name).Inc()

	err := spec.Storage.Store(ca, keyPair)
	if err != nil {
		SpecWriteFailureCount.WithLabelValues(spec.Name).Inc()
		return err
	}
	spec.updateCAExpiry(ca.NotAfter)
	spec.updateCertExpiry(keyPair.Leaf.NotAfter)
	return nil
}

// fetchNewKeyPair request a fresh certificate/key from the transport, backing off as needed.
func (spec *Spec) fetchNewKeyPair() (*tls.Certificate, error) {

	// use exponential backoff rather than using cfssl's backoff implementation; that implementation
	// can back off up to an hour before returning control back to the invoker; that isn't
	// desirable.  If we can't get the requests in in a timely fashion, we'll wake up and
	// revisit via our own scheduling.

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = backoffMaxDelay
	err := backoff.Retry(
		func() error {
			err := spec.tr.RefreshKeys()
			if err != nil {
				SpecRequestFailureCount.WithLabelValues(spec.Name).Inc()
				if isAuthError(err) {
					log.Errorf("spec %s: authentication error. Giving up without retries", spec)
					return backoff.Permanent(errors.WithMessage(err, "error from gatewayca"))
				}
				log.Warningf("spec %s: failed fetching new cert: %s", spec, err)
			}
			return nil
		},
		b,
	)

	if err != nil {
		return nil, errors.WithMessage(err, "errors while fetching certificate/key")
	}

	pair, err := spec.tr.Provider.X509KeyPair()
	if err != nil {
		log.Errorf("spec %s: likely internal error, fetched new cert/key but couldn't create a keypair from it: %s", spec, err)
	}
	return &pair, err
}

func (spec *Spec) updateCertExpiry(notAfter time.Time) {
	spec.expiry.Cert = notAfter
	SpecExpires.WithLabelValues(spec.Name, "cert").Set(float64(notAfter.Unix()))
}

func (spec *Spec) updateCAExpiry(notAfter time.Time) {
	spec.expiry.CA = notAfter
	SpecExpires.WithLabelValues(spec.Name, "ca").Set(float64(notAfter.Unix()))
}

// Run starts monitoring and enforcement of this spec's on disk PKI.
func (spec *Spec) Run(ctx context.Context) {
	// initialize our run   At this point an observer knows this spec is 'alive' and being enforced.
	SpecExpiresBeforeThreshold.WithLabelValues(spec.Name).Set(float64(spec.Before.Seconds()))

	// cleanup our runtime metrics on the way out so the observer knows we're no longer enforcing.
	defer spec.WipeMetrics()

	err := spec.UpdateIfNeeded()
	if err != nil {
		log.Errorf("spec %s: continuing despite failed initial validation due to %s", spec, err)
	}

	rng := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
	sleepPeriod := spec.Interval
	if spec.InitialSplay != 0 {
		sleepPeriod = time.Duration(rng.Float64() * float64(spec.InitialSplay.Nanoseconds()))
		log.Infof("spec %s: initial splay will be used.", spec)
	}
	for {
		log.Infof("spec %s: Next check will be in %s", spec, sleepPeriod)
		SpecNextWake.WithLabelValues(spec.Name).Set(float64(time.Now().Add(sleepPeriod).Unix()))

		select {
		case <-time.After(sleepPeriod):
			log.Debugf("spec %s: woke, starting enforcement", spec)

			// fire wake notifications so things like "spec no longer exists on disk" are checked
			// and logged if relevant.
			for _, callback := range spec.WakeCallbacks {
				callback()
			}

			err := spec.UpdateIfNeeded()
			if err != nil {
				log.Errorf("failed processing %s due to %s", spec, err)
			}
			sleepPeriod = spec.Interval
			if spec.IntervalSplay != 0 {
				i := sleepPeriod.Nanoseconds()
				i += int64(rng.Float64() * float64(spec.IntervalSplay.Nanoseconds()))
				sleepPeriod = time.Duration(int64(i))
			}
		case <-ctx.Done():
			log.Debugf("spec %s: stopping monitoring due to %s", spec, ctx.Err())
			return
		}
	}
}
