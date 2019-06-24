// Package cert contains certificate specifications and
// certificate-specific management.
package cert

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"strings"

	"github.com/cloudflare/cfssl/api/client"
	"github.com/cloudflare/cfssl/info"
	"github.com/cloudflare/cfssl/log"
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

// getPEM is for testing only!
// Getter for CA cert PEM
func (ca *CA) getPEM() []byte {
	return ca.pem
}

// setPEM is for testing only!
// Setter for CA cert PEM
func (ca *CA) setPEM(pem []byte) {
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

	cert := []byte(strings.TrimSpace(resp.Certificate))
	// add a trailing newline for humans
	if !bytes.HasSuffix(cert, []byte{'\n'}) {
		cert = append(cert, '\n')
	}
	return cert, nil
}

// Load reads the CA certificate from the configured remote, and if a
// File section is present in the config, it will attempt to write the
// CA certificate to disk.
func (ca *CA) Load() error {
	if ca.File != nil {
		pem, err := ca.File.ReadFile()
		if err != nil && os.IsNotExist(err) {
			log.Debugf("no CA exists on disk for %s, ignoring", ca.File.Path)
			err = nil
		}
		if err == nil {
			ca.pem = pem
			ca.File.setPermissions()
		}
		return err
	}
	log.Debug("cert: no CA file provided, won't write the CA file to disk")
	return nil
}

// Refresh fetches the latest CA cert. If it has changed, write the
// new CA cert and return true.
func (ca *CA) Refresh() (bool, error) {
	cert, err := ca.getRemoteCert()
	if err != nil {
		return false, err
	}
	// add a trailing newline for human readability
	if !bytes.HasSuffix(cert, []byte{'\n'}) {
		cert = append(cert, '\n')
	}

	updated := len(ca.pem) == 0

	if !updated {
		same, err := CompareCertificates(cert, ca.pem)
		if err != nil {
			log.Warning("cert: error comparing CA certificates: %s", err)
			return true, err
		}
		updated = !same
	}

	if !updated {
		return false, nil
	}
	log.Debugf("ca has changed")
	if ca.File == nil {
		ca.pem = cert
		return true, nil
	}
	err = ca.File.WriteFile(cert)
	if err == nil {
		ca.pem = cert
	}
	return true, err
}
