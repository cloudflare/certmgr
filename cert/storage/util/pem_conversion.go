package util

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// EncodeKeyToPem marshalls a private key into PEM format.
func EncodeKeyToPem(key interface{}) ([]byte, error) {
	switch key.(type) {
	case *ecdsa.PrivateKey:
		data, err := x509.MarshalECPrivateKey(key.(*ecdsa.PrivateKey))
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: data,
			},
		), nil
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey)),
			},
		), nil
	}
	return nil, errors.New("private key is neither ecdsa nor rsa thus cannot be encoded")
}

// EncodeCertificateToPEM serialize a certificate into pem format
func EncodeCertificateToPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		},
	)
}
