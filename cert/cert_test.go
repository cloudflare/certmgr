package cert

import (
	"io/ioutil"
	"strings"
	"testing"

	"github.com/cloudflare/certmgr/cert"
)

var (
	ca1 = &cert.CA{
		Name:        "test_ca",
		Remote:      "test_remote",
		Label:       "test_label",
		Profile:     "test_profile",
		AuthKey:     "1111",
		AuthKeyFile: "test_keyfile",
		File:        nil,
	}
	ca2 = &cert.CA{
		Name:        "test_ca",
		Remote:      "test_remote",
		Label:       "test_label",
		Profile:     "test_profile",
		AuthKey:     "1111",
		AuthKeyFile: "test_keyfile",
		File:        nil,
	}
)

func TestCompareCertificatesInnerNewlines(t *testing.T) {
	dat1, err := ioutil.ReadFile("test_files/google.pem")
	if err != nil {
		t.Fatal(err)
	}
	pem := string(dat1)

	dat2, err := ioutil.ReadFile("test_files/inner-newlines.pem")
	if err != nil {
		t.Fatal(err)
	}
	pemNewline := string(dat2)

	ca1.SetPEM([]byte(pem))
	ca2.SetPEM([]byte(pemNewline))
	isSame, err := cert.CompareCertificates(ca1.GetPEM(), ca2.GetPEM())
	if err != nil {
		t.Fatal(err)
	}
	if !isSame {
		t.Fatal("Duplicate certificates do not match")
	}
}

func TestCompareCertificateOuterNewlines(t *testing.T) {
	dat1, err := ioutil.ReadFile("test_files/google.pem")
	if err != nil {
		t.Fatal(err)
	}
	pem := string(dat1)

	dat2, err := ioutil.ReadFile("test_files/outer-newlines.pem")
	if err != nil {
		t.Fatal(err)
	}
	pemNewline := string(dat2)

	ca1.SetPEM([]byte(pem))
	ca2.SetPEM([]byte(pemNewline))
	isSame, err := cert.CompareCertificates(ca1.GetPEM(), ca2.GetPEM())
	if err != nil {
		t.Fatal(err)
	}
	if !isSame {
		t.Fatal("Duplicate certificates do not match")
	}
}

func TestCompareCertificateDifferent(t *testing.T) {
	dat1, err := ioutil.ReadFile("test_files/google.pem")
	if err != nil {
		t.Fatal(err)
	}
	googlePem := string(dat1)

	dat2, err := ioutil.ReadFile("test_files/digicert.pem")
	if err != nil {
		t.Fatal(err)
	}
	digicertPem := string(dat2)

	ca1.SetPEM([]byte(googlePem))
	ca2.SetPEM([]byte(digicertPem))
	isSame, err := cert.CompareCertificates(ca1.GetPEM(), ca2.GetPEM())
	if err != nil {
		t.Fatal(err)
	}
	if isSame {
		t.Fatal("Different certificates match")
	}
}

func TestCompareCertificateNil(t *testing.T) {
	dat1, err := ioutil.ReadFile("test_files/digicert.pem")
	if err != nil {
		t.Fatal(err)
	}
	digicertPem := string(dat1)

	ca1.SetPEM([]byte(digicertPem))
	ca2.SetPEM(nil)
	isSame, err := cert.CompareCertificates(ca1.GetPEM(), ca2.GetPEM())
	if strings.Compare(err.Error(), "Unable to pem decode certificate") != 0 || isSame {
		t.Fatal(err)
	}
}

func TestCompareCertificateEmpty(t *testing.T) {
	dat1, err := ioutil.ReadFile("test_files/google.pem")
	if err != nil {
		t.Fatal(err)
	}
	googlePem := string(dat1)

	ca1.SetPEM([]byte(googlePem))
	ca2.SetPEM([]byte{})
	isSame, err := cert.CompareCertificates(ca1.GetPEM(), ca2.GetPEM())
	if strings.Compare(err.Error(), "Unable to pem decode certificate") != 0 || isSame {
		t.Fatal(err)
	}
}
