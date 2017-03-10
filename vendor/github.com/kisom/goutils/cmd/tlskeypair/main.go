package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/kisom/goutils/die"
)

var validPEMs = map[string]bool{
	"PRIVATE KEY":     true,
	"RSA PRIVATE KEY": true,
	"EC PRIVATE KEY":  true,
}

const (
	curveInvalid = iota // any invalid curve
	curveRSA            // indicates key is an RSA key, not an EC key
	curveP256
	curveP384
	curveP521
)

func getECCurve(pub interface{}) int {
	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			return curveP256
		case elliptic.P384():
			return curveP384
		case elliptic.P521():
			return curveP521
		default:
			return curveInvalid
		}
	case *rsa.PublicKey:
		return curveRSA
	default:
		return curveInvalid
	}
}

func loadKey(path string) (crypto.Signer, error) {
	in, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	in = bytes.TrimSpace(in)
	p, _ := pem.Decode(in)
	if p != nil {
		if !validPEMs[p.Type] {
			return nil, errors.New("invalid private key file type " + p.Type)
		}
		in = p.Bytes
	}

	priv, err := x509.ParsePKCS8PrivateKey(in)
	if err != nil {
		priv, err = x509.ParsePKCS1PrivateKey(in)
		if err != nil {
			priv, err = x509.ParseECPrivateKey(in)
			if err != nil {
				return nil, err
			}
		}
	}

	switch priv.(type) {
	case *rsa.PrivateKey:
		return priv.(*rsa.PrivateKey), nil
	case *ecdsa.PrivateKey:
		return priv.(*ecdsa.PrivateKey), nil
	}

	// should never reach here
	return nil, errors.New("invalid private key")

}

func main() {
	var keyFile, certFile string
	flag.StringVar(&keyFile, "k", "", "TLS private `key` file")
	flag.StringVar(&certFile, "c", "", "TLS `certificate` file")
	flag.Parse()

	in, err := ioutil.ReadFile(certFile)
	die.If(err)

	p, _ := pem.Decode(in)
	if p != nil {
		if p.Type != "CERTIFICATE" {
			die.With("invalid certificate (type is %s)", p.Type)
		}
		in = p.Bytes
	}
	cert, err := x509.ParseCertificate(in)
	die.If(err)

	priv, err := loadKey(keyFile)
	die.If(err)

	switch pub := priv.Public().(type) {
	case *rsa.PublicKey:
		switch certPub := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			if pub.N.Cmp(certPub.N) != 0 || pub.E != certPub.E {
				fmt.Println("No match (public keys don't match).")
				os.Exit(1)
			}
			fmt.Println("Match.")
			return
		case *ecdsa.PublicKey:
			fmt.Println("No match (RSA private key, EC public key).")
			os.Exit(1)
		}
	case *ecdsa.PublicKey:
		privCurve := getECCurve(pub)
		certCurve := getECCurve(cert.PublicKey)
		log.Printf("priv: %d\tcert: %d\n", privCurve, certCurve)

		if certCurve == curveRSA {
			fmt.Println("No match (private key is EC, certificate is RSA).")
			os.Exit(1)
		} else if privCurve == curveInvalid {
			fmt.Println("No match (invalid private key curve).")
			os.Exit(1)
		} else if privCurve != certCurve {
			fmt.Println("No match (EC curves don't match).")
			os.Exit(1)
		}

		certPub := cert.PublicKey.(*ecdsa.PublicKey)
		if pub.X.Cmp(certPub.X) != 0 {
			fmt.Println("No match (public keys don't match).")
			os.Exit(1)
		}

		if pub.Y.Cmp(certPub.Y) != 0 {
			fmt.Println("No match (public keys don't match).")
			os.Exit(1)
		}

		fmt.Println("Match.")
	default:
		fmt.Printf("Unrecognised private key type: %T\n", priv.Public())
		os.Exit(1)
	}
}
