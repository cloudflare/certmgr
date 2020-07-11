package storage

import (
	"io/ioutil"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/cloudflare/certmgr/cert/storage/util"
)

func getFilesAndPaths(ca, cert, key string) (caFile *util.CertificateFile, certFile *util.CertificateFile, keyFile *util.File, paths []string) {
	if ca != "" {
		caFile = &util.CertificateFile{File: util.File{Path: ca}}
		paths = append(paths, ca)
	}
	if cert != "" {
		certFile = &util.CertificateFile{File: util.File{Path: cert}}
		paths = append(paths, cert)
	}
	if key != "" {
		keyFile = &util.File{Path: key}
		paths = append(paths, key)
	}
	return
}

func TestFileBackend(t *testing.T) {
	tests := []struct {
		name string
		ca   string
		cert string
		key  string
		fail bool
	}{
		{"just ca", "/ca", "", "", false},
		{"just certs", "", "/cert", "/key", false},
		{"all", "/ca", "/cert", "/key", false},
		{"missing key", "", "/cert", "", true},
		{"missing cert", "", "", "/key", true},
		{"all missing", "", "", "", true},
		{"reused path1", "", "/reused", "/reused", true},
		{"reused path2", "/reused", "/reused", "/path2", true},
		{"reused path3", "/reused", "/path2", "/reused", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ca, cert, key, expectedPaths := getFilesAndPaths(test.ca, test.cert, test.key)

			fb, err := NewFileBackend("testspec", ca, cert, key)
			if test.fail {
				if err == nil {
					t.Fatal("Error wasn't returned")
				}
				return
			} else if err != nil {
				t.Fatalf("unexpected err returned from init: %s", err)
			}
			if (test.key != "") != fb.WantsKeyPair() {
				t.Fatalf("WantsKeyPair returned %t, expects %t", fb.WantsKeyPair(), test.key != "")
			}

			sort.Strings(expectedPaths)
			returnedPaths := fb.GetPaths()
			sort.Strings(returnedPaths)
			if !reflect.DeepEqual(expectedPaths, returnedPaths) {
				t.Fatalf("wanted %v from GetPaths, got %v", expectedPaths, returnedPaths)
			}
			tmpDir, err := ioutil.TempDir("", "tests")
			if err != nil {
				t.Fatalf("failed to create tempdir: %s", err)
			}
			defer os.RemoveAll(tmpDir)
			existingCA, existingKeyPair, err := fb.Load()
			if existingCA != nil || existingKeyPair != nil {
				t.Fatalf("initial Load() returned non-nill CA=%v keyPair=%v", existingCA, existingKeyPair)
			}
			if err == nil {
				t.Fatalf("didn't receive err from initial empty Load")
			}
			// todo; write actual tests for generating PKI and verifying the backend persists/returns it properly.
		})
	}
}
