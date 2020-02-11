package cert

import (
	"crypto/x509"
	"net"
	"testing"
)

// TestCertificateMatchesHostname validates CertificateMatchesHostname logic
func TestCertificateMatchesHostname(t *testing.T) {
	assert := func(a, b []string, desired bool) {
		cert := x509.Certificate{}
		for idx := range b {
			ip := net.ParseIP(b[idx])
			if ip == nil {
				cert.DNSNames = append(cert.DNSNames, b[idx])
			} else {
				cert.IPAddresses = append(cert.IPAddresses, ip)
			}
		}
		if CertificateMatchesHostname(a, &cert) != desired {
			if desired {
				t.Fatalf("%v != %v", a, b)
			} else {
				t.Fatalf("%v == %v", a, b)
			}
		}
	}
	// check the basics
	assert([]string{"a.com"}, []string{"a.com"}, true)
	assert([]string{"a.com"}, []string{"b.com"}, false)
	assert([]string{"a.com", "b.com"}, []string{"a.com", "b.com"}, true)
	assert([]string{"a.com", "b.com"}, []string{"b.com", "a.com"}, true)
	assert([]string{"a.com", "b.com"}, []string{"b.com"}, false)
	assert([]string{"a.com", "b.com"}, []string{"a.com"}, false)
	assert([]string{"b.com"}, []string{"a.com", "b.com"}, false)
	assert([]string{"a.com", "b.com", "c.org"}, []string{"a.com"}, false)
	assert([]string{"a.com", "b.com", "c.org"}, []string{"a.com", "c.org", "b.com"}, true)

	// check IP behaviours...
	assert([]string{"a.com"}, []string{"192.168.0.1"}, false)
	assert([]string{"192.168.0.1"}, []string{"192.168.0.1"}, true)
	assert([]string{"2001:db8::1"}, []string{"2001:db8::1"}, true)
	assert([]string{"2001:db8::1", "a.corp"}, []string{"a.corp", "2001:db8::1"}, true)
	// check that it properly handles ipv6 addresses that have inconsistent shortening
	assert([]string{"2001:db8:0000::1"}, []string{"2001:db8::1"}, true)
	assert([]string{"2001:db8::1", "a.corp"}, []string{"2001:db8:0000::1", "a.corp"}, true)
	assert([]string{"2001:db8::1", "a.corp"}, []string{"a.corp", "2001:db8:0000::2"}, false)
	assert([]string{"2001:db8::2", "a.corp"}, []string{"2001:db8::1", "a.corp"}, false)
	assert([]string{"2001:db8::1", "a.corp"}, []string{"b.corp", "2001:db8::1"}, false)
}
