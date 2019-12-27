// Package cert contains certificate specifications and
// certificate-specific management.
package cert

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"time"

	"github.com/cloudflare/cfssl/api/client"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/info"
	"github.com/cloudflare/cfssl/transport"
	"github.com/cloudflare/cfssl/transport/core"
	"github.com/pkg/errors"
)

// An Authority contains the core details for a CFSSL CA.
type Authority struct {
	Remote  string `json:"remote" yaml:"remote"`
	Label   string `json:"label" yaml:"label"`
	Profile string `json:"profile" yaml:"profile"`
	AuthKey string `json:"auth_key" yaml:"auth_key"`

	// RootCACert if specified is a CA to use for interactions with cfssl.
	// If not specified, host CA trust is used.
	RootCACert string `json:"root_ca,omitempty" yaml:"root_ca,omitempty"`
}

func (a *Authority) createIdentityStub() *core.Identity {
	return &core.Identity{
		Roots: []*core.Root{
			&core.Root{
				Type: "system",
			},
			&core.Root{
				Type: "cfssl",
				Metadata: map[string]string{
					"host":          a.Remote,
					"profile":       a.Profile,
					"label":         a.Label,
					"tls-remote-ca": a.RootCACert,
				},
			},
		},
		Profiles: map[string]map[string]string{
			"cfssl": map[string]string{
				"remote":        a.Remote,
				"profile":       a.Profile,
				"label":         a.Label,
				"tls-remote-ca": a.RootCACert,
				"auth-type":     "standard",
				"auth-key":      a.AuthKey,
			},
		},
	}
}

// CreateTransport converts an Authority and CertificateRequest into a cfssl transport for usage.
func (a *Authority) CreateTransport(before time.Duration, request *csr.CertificateRequest) (*transport.Transport, error) {
	ident := a.createIdentityStub()
	ident.Request = request
	return transport.New(before, ident)
}

func (a *Authority) getRemoteCert() (*x509.Certificate, error) {
	var tlsConfig *tls.Config
	if a.RootCACert != "" {
		rootCABytes, err := ioutil.ReadFile(a.RootCACert)
		if err != nil {
			return nil, errors.WithMessage(err, "failed reading RootCACert")
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

	remote := client.NewServerTLS(a.Remote, tlsConfig)
	infoReq := &info.Req{
		Label:   a.Label,
		Profile: a.Profile,
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
