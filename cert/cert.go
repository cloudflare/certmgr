// Package cert contains certificate specifications and
// certificate-specific management.
package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/transport"
	"github.com/cloudflare/cfssl/transport/core"
)

// A CA contains the core details for a CFSSL CA.
type CA struct {
	Remote  string `json:"remote"`
	Label   string `json:"label"`
	Profile string `json:"profile"`
	AuthKey string `json:"auth_key"`
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
	// this field is not empty, the service will be restarted upon
	// certificate renewal.
	Service string                  `json:"service"`
	Action  string                  `json:"action"`
	Request *csr.CertificateRequest `json:"request"`
	Key     *File                   `json:"private_key"`
	Cert    *File                   `json:"certificate"`
	CA      CA                      `json:"authority"`

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

// Load reads a spec from a JSON configuration file.
func Load(path, remote string, before time.Duration) (*Spec, error) {
	in, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var spec = &Spec{
		Request: csr.New(),
	}

	err = json.Unmarshal(in, spec)
	if err != nil {
		return nil, err
	}

	if spec.CA.Remote == "" {
		spec.CA.Remote = remote
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
		log.Debugf("cert: %s", err)
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

// Ready returns true if the key pair specified by the Spec exists; it
// doesn't check whether it needs to be renewed.
func (spec *Spec) Ready() bool {
	if spec.tr == nil {
		panic("cert: cannot check readiness because spec has an invalid transport")
	}
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
