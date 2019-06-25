// Package cert contains certificate specifications and
// certificate-specific management.
package cert

import (
	"crypto/x509/pkix"
	"fmt"
	"sort"
	"strings"
)

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

// Compare if hostnames in certificate and spec are equal
func hostnamesEquals(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sort.Strings(a)
	sort.Strings(b)
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
