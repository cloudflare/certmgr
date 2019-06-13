// Package cert contains certificate specifications and
// certificate-specific management.
package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

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
