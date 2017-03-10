package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/revoke"
	"github.com/kisom/goutils/die"
	"github.com/kisom/goutils/lib"
)

func printRevocation(cert *x509.Certificate) {
	remaining := cert.NotAfter.Sub(time.Now())
	fmt.Printf("certificate expires in %s.\n", lib.Duration(remaining))

	revoked, ok := revoke.VerifyCertificate(cert)
	if !ok {
		fmt.Fprintf(os.Stderr, "[!] the revocation check failed (failed to determine whether certificate\nwas revoked)")
		return
	}

	if revoked {
		fmt.Fprintf(os.Stderr, "[!] the certificate has been revoked\n")
		return
	}
}

func main() {
	var caFile, intFile string
	var forceIntermediateBundle, revexp, verbose bool
	flag.StringVar(&caFile, "ca", "", "CA certificate `bundle`")
	flag.StringVar(&intFile, "i", "", "intermediate `bundle`")
	flag.BoolVar(&forceIntermediateBundle, "f", false,
		"force the use of the intermediate bundle, ignoring any intermediates bundled with certificate")
	flag.BoolVar(&revexp, "r", false, "print revocation and expiry information")
	flag.BoolVar(&verbose, "v", false, "verbose")
	flag.Parse()

	var roots *x509.CertPool
	if caFile != "" {
		var err error
		if verbose {
			fmt.Println("[+] loading root certificates from", caFile)
		}
		roots, err = helpers.LoadPEMCertPool(caFile)
		die.If(err)
	}

	var ints *x509.CertPool
	if intFile != "" {
		var err error
		if verbose {
			fmt.Println("[+] loading intermediate certificates from", intFile)
		}
		ints, err = helpers.LoadPEMCertPool(caFile)
		die.If(err)
	} else {
		ints = x509.NewCertPool()
	}

	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [-ca bundle] [-i bundle] cert",
			lib.ProgName())
	}

	fileData, err := ioutil.ReadFile(flag.Arg(0))
	die.If(err)

	chain, err := helpers.ParseCertificatesPEM(fileData)
	die.If(err)
	if verbose {
		fmt.Printf("[+] %s has %d certificates\n", flag.Arg(0), len(chain))
	}

	cert := chain[0]
	if len(chain) > 1 {
		if !forceIntermediateBundle {
			for _, intermediate := range chain[1:] {
				if verbose {
					fmt.Printf("[+] adding intermediate with SKI %x\n", intermediate.SubjectKeyId)
				}

				ints.AddCert(intermediate)
			}
		}
	}

	opts := x509.VerifyOptions{
		Intermediates: ints,
		Roots:         roots,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	_, err = cert.Verify(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Verification failed: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Println("OK")
	}

	if revexp {
		printRevocation(cert)
	}
}
