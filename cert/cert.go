// Package cert contains certificate specifications and
// certificate-specific management.
package cert

import (
	"bytes"
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

	"github.com/cloudflare/cfssl/api/client"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/info"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/transport"
	"github.com/cloudflare/cfssl/transport/core"
)

// A CA contains the core details for a CFSSL CA. There are two ways
// to use this: fill out Name to refer to a global CA (e.g. as defined
// in the config file) or fill out Remote, Label, Profile, and AuthKey.
type CA struct {
	Name        string `json:"name" yaml:"name"`
	Remote      string `json:"remote" yaml:"remote"`
	Label       string `json:"label" yaml:"label"`
	Profile     string `json:"profile" yaml:"profile"`
	AuthKey     string `json:"auth_key" yaml:"auth_key"`
	AuthKeyFile string `json:"auth_key_file" yaml:"auth_key_file"`
	File        *File  `json:"file,omitempty" yaml:"file,omitempty"`
	pem         []byte
	loaded      bool
}

func (ca *CA) getRemoteCert() ([]byte, error) {
	remote := client.NewServer(ca.Remote)
	infoReq := &info.Req{
		Label:   ca.Label,
		Profile: ca.Profile,
	}

	serialisedRequest, err := json.Marshal(infoReq)
	if err != nil {
		return nil, err
	}

	resp, err := remote.Info(serialisedRequest)
	if err != nil {
		return nil, err
	}

	return []byte(strings.TrimSpace(resp.Certificate)), nil
}

func (ca *CA) writeCert(cert []byte) error {
	if ca.File == nil {
		return nil
	}

	ca.File.Path = filepath.Clean(ca.File.Path)
	err := ca.File.Parse(fmt.Sprintf("CA:%s/%s/%s", ca.Remote, ca.Label, ca.Profile))
	if err != nil {
		return err
	}

	maybeExisting, err := ioutil.ReadFile(ca.File.Path)
	if err == nil {
		if !bytes.Equal(maybeExisting, cert) {
			err = ioutil.WriteFile(ca.File.Path, cert, 0644)
			if err != nil {
				return err
			}
			log.Infof("cert: wrote CA certificate: %s", ca.File.Path)
		} else {
			log.Infof("cert: existing CA certificate at %s is current, won't overwrite",
				ca.File.Path)
		}
	} else if os.IsNotExist(err) {
		err = ioutil.WriteFile(ca.File.Path, cert, 0644)
		if err != nil {
			return err
		}
		log.Infof("cert: wrote CA certificate: %s", ca.File.Path)
	}

	if err != nil {
		return err
	}

	err = ca.File.Set()
	return err
}

// Load reads the CA certificate from the configured remote, and if a
// File section is present in the config, it will attempt to write the
// CA certificate to disk.
func (ca *CA) Load() error {
	cert, err := ca.getRemoteCert()
	if err != nil {
		log.Errorf("cert: failed to fetch remote CA: %s", err)
		return err
	}

	if ca.File == nil {
		// NB: this used to be an info message, but it caused
		// more confusion than anything else.
		ca.pem = cert
		log.Debug("cert: no CA file provided, won't write the CA file to disk")
		return nil
	}

	err = ca.writeCert(cert)
	if err != nil {
		return err
	}

	ca.loaded = true
	return nil
}

// Refresh fetches the latest CA cert. If it has changed, write the
// new CA cert and return true.
func (ca *CA) Refresh() (changed bool, err error) {
	cert, err := ca.getRemoteCert()
	if err != nil {
		return
	}

	if bytes.Equal(cert, ca.pem) {
		return
	}
	changed = true

	if ca.File == nil {
		return
	}

	ca.pem = cert
	err = ca.writeCert(ca.pem)
	return
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

	// This defines the service manager to use.  This should be defined
	// globally rather than per cert- it's allowed here to allow cert
	// definitions to use a servicemanager of 'command' to allow freeform
	// invocations.
	ServiceManager string `json:"svcmgr" yaml:"svcmgr"`

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
func (spec *Spec) Identity() (*core.Identity, error) {
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

	err = spec.Key.Parse("private_key")
	if err != nil {
		return nil, err
	}

	err = spec.Cert.Parse("certificate")
	if err != nil {
		return nil, err
	}

	spec.Key.Path = filepath.Clean(spec.Key.Path)
	spec.Cert.Path = filepath.Clean(spec.Cert.Path)

	err = spec.CA.Load()
	if err != nil {
		return nil, err
	}

	identity, err := spec.Identity()
	if err != nil {
		return nil, err
	}
	spec.tr, err = transport.New(before, identity)
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

	// This bit of code is necessary to confirm that the cert/key are older than the spec definition.
	specStat, err := os.Stat(spec.Path)
	if err != nil {
		// The assertion here is that the spec actually
		// exists. If it doesn't, something is wrong with the
		// world.
		panic("cert: certificate spec doesn't exist during RefreshKeys()")
	}

	isTooOld := func(path string) bool {
		st, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				log.Errorf("while checking cert/key path %s, got path error %s", path, err)
			}
			return true
		}
		if specStat.ModTime().After(st.ModTime()) {
			log.Infof("refreshing due to spec %s having a newer mtime then %s", spec.Path, path)
			return true
		}
		return false
	}
	if isTooOld(spec.Key.Path) || isTooOld(spec.Cert.Path) {
		// This is necessary to essentially force cfssl to regenerate since it's not spec aware.
		spec.tr.Provider.Certificate().NotAfter = specStat.ModTime()
		return 0
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
