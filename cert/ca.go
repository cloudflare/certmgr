// Package cert contains certificate specifications and
// certificate-specific management.
package cert

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"

	"github.com/cloudflare/cfssl/api/client"
	"github.com/cloudflare/cfssl/info"
)

// A CA contains the core details for a CFSSL CA. There are two ways
// to use this: fill out Name to refer to a global CA (e.g. as defined
// in the config file) or fill out Remote, Label, Profile, and AuthKey.
type CA struct {
	Name        string           `json:"name" yaml:"name"`
	Remote      string           `json:"remote" yaml:"remote"`
	Label       string           `json:"label" yaml:"label"`
	Profile     string           `json:"profile" yaml:"profile"`
	AuthKey     string           `json:"auth_key" yaml:"auth_key"`
	AuthKeyFile string           `json:"auth_key_file" yaml:"auth_key_file"`
	File        *CertificateFile `json:"file,omitempty" yaml:"file,omitempty"`
	RootCACert  string           `json:"root_ca,omitempty" yaml:"root_ca,omitempty"`
}

func (ca *CA) getRemoteCert() (*x509.Certificate, error) {
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

	certPem, _ := pem.Decode([]byte(resp.Certificate))
	if certPem == nil {
		return nil, errors.New("failed to pem parse returned CA")
	}
	return x509.ParseCertificate(certPem.Bytes)
}
