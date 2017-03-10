package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/kisom/goutils/die"
)

func main() {
	flag.Parse()

	for _, fileName := range flag.Args() {
		in, err := ioutil.ReadFile(fileName)
		die.If(err)

		if p, _ := pem.Decode(in); p != nil {
			if p.Type != "CERTIFICATE REQUEST" {
				log.Fatal("INVALID FILE TYPE")
			}
			in = p.Bytes
		}

		csr, err := x509.ParseCertificateRequest(in)
		die.If(err)

		out, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
		die.If(err)

		var t string
		switch pub := csr.PublicKey.(type) {
		case *rsa.PublicKey:
			t = "RSA PUBLIC KEY"
		case *ecdsa.PublicKey:
			t = "EC PUBLIC KEY"
		default:
			die.With("unrecognised public key type %T", pub)
		}

		p := &pem.Block{
			Type:  t,
			Bytes: out,
		}

		err = ioutil.WriteFile(fileName+".pub", pem.EncodeToMemory(p), 0644)
		die.If(err)
		fmt.Printf("[+] wrote %s.\n", fileName+".pub")
	}
}
