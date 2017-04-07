// Package cert contains certificate specifications and
// certificate-specific management.
package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v1"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/transport"
	"github.com/cloudflare/cfssl/transport/core"
)

// A CA contains the core details for a CFSSL CA.
type CA struct {
	Remote  string `json:"remote" yaml:"remote"`
	Label   string `json:"label" yaml:"label"`
	Profile string `json:"profile" yaml:"profile"`
	AuthKey string `json:"auth_key" yaml:"auth_key"`
}

func displayName(name pkix.Name) string {
	var ns []string

	if name.CommonName != "" {
		ns = append(ns, name.CommonName)
	}

	for i := range name.Country {
		ns = append(ns, fmt.Sprintf("C=%s", name.Country[i]))
	}

	for i := range name.Organization {
		ns = append(ns, fmt.Sprintf("O=%s", name.Organization[i]))
	}

	for i := range name.OrganizationalUnit {
		ns = append(ns, fmt.Sprintf("OU=%s", name.OrganizationalUnit[i]))
	}

	for i := range name.Locality {
		ns = append(ns, fmt.Sprintf("L=%s", name.Locality[i]))
	}

	for i := range name.Province {
		ns = append(ns, fmt.Sprintf("ST=%s", name.Province[i]))
	}

	if len(ns) > 0 {
		return "/" + strings.Join(ns, "/")
	}

	return ""
}

// A Spec contains information needed to monitor and renew a
// certificate.
type Spec struct {
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
	Cert *File `json:"certificate" yaml:"certificate"`

	// CA specifies the certificate authority that should be used.
	CA CA `json:"authority" yaml:"authority"`

	// Path points to the on-disk location of the certificate
	// spec.
	Path string

	queued  bool
	expires time.Time
	tr      *transport.Transport
}

func (spec *Spec) String() string {
	name := displayName(spec.Request.Name())
	if name == "" {
		name = spec.Service
	}

	if name == "" {
		name = spec.Cert.Path
	}

	return name
}

// Identity creates a transport package identity for the certificate.
func (spec *Spec) Identity() *core.Identity {
	ident := &core.Identity{
		Request: spec.Request,
		Roots: []*core.Root{
			&core.Root{
				Type: "system",
			},
			&core.Root{
				Type: "cfssl",
				Metadata: map[string]string{
					"host":    spec.CA.Remote,
					"profile": spec.CA.Profile,
					"label":   spec.CA.Label,
				},
			},
		},
		Profiles: map[string]map[string]string{
			"cfssl": map[string]string{
				"remote":  spec.CA.Remote,
				"profile": spec.CA.Profile,
				"label":   spec.CA.Label,
			},
			"paths": map[string]string{
				"private_key": spec.Key.Path,
				"certificate": spec.Cert.Path,
			},
		},
	}

	if spec.CA.AuthKey != "" {
		ident.Profiles["cfssl"]["auth-type"] = "standard"
		ident.Profiles["cfssl"]["auth-key"] = spec.CA.AuthKey
	}

	return ident
}

func readCertFile(path string) (*Spec, error) {
	in, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var spec = &Spec{
		Request: csr.New(),
		Path:    path,
	}

	switch filepath.Ext(path) {
	case ".json":
		err = json.Unmarshal(in, &spec)
	case ".yml", ".yaml":
		err = yaml.Unmarshal(in, &spec)
	default:
		err = fmt.Errorf("cert: unrecognised spec file format for %s", path)
	}

	return spec, err
}

// Load reads a spec from a JSON configuration file.
func Load(path, remote string, before time.Duration) (*Spec, error) {
	spec, err := readCertFile(path)
	if err != nil {
		return nil, err
	}

	if spec.CA.Remote == "" {
		spec.CA.Remote = remote
	}

	if spec.CA.Remote == "" {
		return nil, errors.New("cert: no remote specified in authority (either in the spec or in the certmgr config)")
	}

	err = spec.Key.parse("private_key")
	if err != nil {
		return nil, err
	}

	err = spec.Cert.parse("certificate")
	if err != nil {
		return nil, err
	}

	spec.Key.Path = filepath.Clean(spec.Key.Path)
	spec.Cert.Path = filepath.Clean(spec.Cert.Path)

	spec.tr, err = transport.New(before, spec.Identity())
	if err != nil {
		return nil, err
	}

	// The provider's Load returning an error here just means that
	// the certificate and private key don't exist yet.
	err = spec.tr.Provider.Load()
	if err != nil {
		err = nil
	}
	return spec, err
}

// RefreshKeys will make sure the key pair in the Spec has loaded keys
// and has a valid certificate. It will handle any persistence, check
// that the certificate is valid (i.e. that its expiry date is within
// the Before date), and handle certificate reissuance as needed.
func (spec *Spec) RefreshKeys() error {
	if spec.tr == nil {
		panic("cert: cannot refresh keys because spec has an invalid transport")
	}

	if !spec.tr.Provider.Persistent() {
		panic("cert: cannot manage ephemeral certificates")
	}

	err := spec.tr.RefreshKeys()
	if err != nil {
		return err
	}

	err = spec.Key.Set()
	if err != nil {
		return err
	}

	err = spec.Cert.Set()
	if err != nil {
		return err
	}

	return nil
}

// If the certificate is older than the spec, it should be
// removed.
func (spec *Spec) removeCertificateIfOutdated() {
	specStat, err := os.Stat(spec.Path)
	if err != nil {
		// The assertion here is that the spec actually
		// exists. If it doesn't, something is wrong with the
		// world.
		panic("cert: certificate spec doesn't exist during readiness check")
	}

	certStat, err := os.Stat(spec.Cert.Path)
	if err != nil {
		// If the certificate doesn't exist, nothing needs to
		// be done.
		return
	}

	// If the spec is newer than the certificate, remove it.
	if !specStat.ModTime().After(certStat.ModTime()) {
		os.Remove(spec.Cert.Path)
	}
}

// Ready returns true if the key pair specified by the Spec exists; it
// doesn't check whether it needs to be renewed.
func (spec *Spec) Ready() bool {
	if spec.tr == nil {
		panic("cert: cannot check readiness because spec has an invalid transport")
	}

	// If the certificate is older than the spec, we should remove
	// it to force an update.
	spec.removeCertificateIfOutdated()

	return spec.tr.Provider.Ready()
}

// Lifespan returns a time.Duration for the certificate's validity.
func (spec *Spec) Lifespan() time.Duration {
	if spec.tr == nil {
		panic("cert: cannot check certificate's lifespan because spec has an invalid transport")
	}
	return spec.tr.Lifespan()
}

// Certificate returns the x509.Certificate associated with the spec
// if one exists.
func (spec *Spec) Certificate() *x509.Certificate {
	if spec.tr == nil {
		panic("cert: cannot retrieve certificate because spec has an invalid transport")
	}

	return spec.tr.Provider.Certificate()
}

// Queue marks the spec as being queued for renewal.
func (spec *Spec) Queue() {
	spec.queued = true
}

// IsQueued returns true if the spec is already queued for renewal.
func (spec *Spec) IsQueued() bool {
	return spec.queued
}

// Dequeue marks the spec as having been removed from the renewal
// queue.
func (spec *Spec) Dequeue() {
	spec.queued = false
}

// Backoff returns the backoff delay.
func (spec *Spec) Backoff() time.Duration {
	return spec.tr.Backoff.Duration()
}

// ResetBackoff resets the spec's backoff.
func (spec *Spec) ResetBackoff() {
	spec.tr.Backoff.Reset()
}
