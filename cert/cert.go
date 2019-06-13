// Package cert contains certificate specifications and
// certificate-specific management.
package cert

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
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
	RootCACert  string `json:"root_ca,omitempty" yaml:"root_ca,omitempty"`
	pem         []byte
}

// GetPEM is for testing only!
// Getter for CA cert PEM
func (ca *CA) GetPEM() []byte {
	return ca.pem
}

// SetPEM is for testing only!
// Setter for CA cert PEM
func (ca *CA) SetPEM(pem []byte) {
	ca.pem = pem
}

func (ca *CA) getRemoteCert() ([]byte, error) {
	var tlsConfig *tls.Config
	if ca.RootCACert != "" {
		rootCABytes, err := ioutil.ReadFile(ca.RootCACert)
		if err != nil {
			return nil, err
		}

		rootCaCertPool := x509.NewCertPool()
		ok := rootCaCertPool.AppendCertsFromPEM(rootCABytes)
		if !ok {
			return nil, errors.New("failed to parse rootCA certs")
		}
		tlsConfig = &tls.Config{
			RootCAs: rootCaCertPool,
		}
	}

	remote := client.NewServerTLS(ca.Remote, tlsConfig)
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

	// add a trailing newline for humans
	if !bytes.HasSuffix(cert, []byte{'\n'}) {
		cert = append(cert, '\n')
	}
	err = ioutil.WriteFile(ca.File.Path, cert, 0644)
	if err != nil {
		return err
	}
	log.Infof("cert: wrote CA certificate: %s", ca.File.Path)

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

	ca.pem, err = ioutil.ReadFile(ca.File.Path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Refresh fetches the latest CA cert. If it has changed, write the
// new CA cert and return true.
func (ca *CA) Refresh() (bool, error) {
	cert, err := ca.getRemoteCert()
	if err != nil {
		return false, err
	}

	isCACertSame, err := CompareCertificates(cert, ca.pem)
	if err != nil {
		log.Warning("cert: error comparing CA certificates")
		return false, err
	}

	if isCACertSame {
		if ca.File != nil {
			log.Infof("cert: existing CA certificate at %s is current", ca.File.Path)
		}
		return false, nil
	}

	// If CA cert has changed, write out new CA cert
	if ca.File != nil {
		err = ca.writeCert(cert)
	}
	// If there were no errors, update our internal notion of what the CA is.
	if err != nil {
		ca.pem = cert
	}
	return true, err
}

// CompareCertificates x509 compares two CA certificates
func CompareCertificates(cert1, cert2 []byte) (bool, error) {
	p1, _ := pem.Decode(cert1)
	if p1 == nil {
		return false, errors.New("Unable to pem decode certificate")
	}
	parsedCert1, err := x509.ParseCertificate(p1.Bytes)
	if err != nil {
		return false, err
	}
	p2, _ := pem.Decode(cert2)
	if p2 == nil {
		return false, errors.New("Unable to pem decode certificate")
	}
	parsedCert2, err := x509.ParseCertificate(p2.Bytes)
	if err != nil {
		return false, err
	}
	return parsedCert1.Equal(parsedCert2), nil
}

func displayName(name pkix.Name) string {
	var ns []string

	if name.CommonName != "" {
		ns = append(ns, name.CommonName)
	}

	for _, val := range name.Country {
		ns = append(ns, fmt.Sprintf("C=%s", val))
	}

	for _, val := range name.Organization {
		ns = append(ns, fmt.Sprintf("O=%s", val))
	}

	for _, val := range name.OrganizationalUnit {
		ns = append(ns, fmt.Sprintf("OU=%s", val))
	}

	for _, val := range name.Locality {
		ns = append(ns, fmt.Sprintf("L=%s", val))
	}

	for _, val := range name.Province {
		ns = append(ns, fmt.Sprintf("ST=%s", val))
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

func newSpecFromPath(path string) (*Spec, error) {
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
	if spec.IsChangedOnDisk(spec.Key.Path) || spec.IsChangedOnDisk(spec.Cert.Path) {
		// This is necessary to essentially force cfssl to regenerate since it's not spec aware.
		log.Infof("refreshing due to spec %s having a newer mtime than key or cert", spec.Path)
		spec.ResetLifespan()
		return 0
	}
	return spec.tr.Lifespan()
}

func (spec *Spec) IsChangedOnDisk(path string) bool {
	specStat, err := os.Stat(spec.Path)
	if err != nil {
		// The assertion here is that the spec actually
		// exists. If it doesn't, something is wrong with the
		// world.
		log.Warning("cert: IsChangedOnDisk: Spec file does not exist")
		return true
	}
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Errorf("cert isChangedOnDisk: while checking path %s, got path error %s", path, err)
		}
		return true
	}
	return specStat.ModTime().After(st.ModTime())
}

// CertExpireTime returns the time at which this spec's Certificate is no
// longer valid.
func (spec *Spec) CertExpireTime() time.Time {
	cert := spec.tr.Provider.Certificate()
	if cert != nil {
		return spec.tr.Provider.Certificate().NotAfter
	}
	return time.Time{}
}

// CertExpireTime returns the time at which this spec's CA is no
// longer valid.
func (spec *Spec) CAExpireTime() time.Time {
	c := spec.CA.pem
	if c == nil {
		log.Debug("spec %s: No CA loaded", spec)
		return time.Time{}
	}
	certPem, _ := pem.Decode(c)
	if certPem == nil {
		log.Debug("spec %s: Unable to pem decode CA certificate", spec)
		return time.Time{}
	}
	parsedCert, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		log.Debug("spec %s: Unable to parse certificate", spec)
		return time.Time{}
	}
	return parsedCert.NotAfter
}

// Reset the lifespan to force cfssl to regenerate
func (spec *Spec) ResetLifespan() {
	cert := spec.tr.Provider.Certificate()
	if cert != nil {
		spec.tr.Provider.Certificate().NotAfter = time.Time{}
	}
}

// Certificate returns the x509.Certificate associated with the spec
// if one exists.
func (spec *Spec) Certificate() *x509.Certificate {
	if spec.tr == nil {
		panic("cert: cannot retrieve certificate because spec has an invalid transport")
	}

	return spec.tr.Provider.Certificate()
}

// Backoff returns the backoff delay.
func (spec *Spec) Backoff() time.Duration {
	return spec.tr.Backoff.Duration()
}

// ResetBackoff resets the spec's backoff.
func (spec *Spec) ResetBackoff() {
	spec.tr.Backoff.Reset()
}
