package cert

import (
	"sort"
	"testing"
)

func TestSpecPaths(t *testing.T) {
	spec := Spec{}
	assert := func(desired, received []string) {
		sort.Strings(desired)
		sort.Strings(received)

		if len(received) != len(desired) {
			t.Fatalf("%s != %s", desired, received)
		}
		for idx := range received {
			if desired[idx] != received[idx] {
				t.Fatalf("%s != %s", desired, received)
			}
		}
	}

	// ensure that an empty spec doesn't trigger a panic
	assert([]string{}, spec.Paths())
	spec.CA.File = &CertificateFile{File{Path: "/ca"}}

	assert([]string{"/ca"}, spec.Paths())
	spec.Cert = &CertificateFile{File{Path: "/cert"}}
	spec.Key = &File{Path: "/key"}

	assert([]string{"/ca", "/key", "/cert"}, spec.Paths())

	spec.CA.File = nil
	assert([]string{"/key", "/cert"}, spec.Paths())
}
