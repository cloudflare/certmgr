package main

import (
	"crypto/tls"
	"encoding/pem"
	"flag"
	"fmt"
	"regexp"

	"github.com/kisom/goutils/die"
)

var hasPort = regexp.MustCompile(`:\d+$`)

func main() {
	flag.Parse()

	for _, server := range flag.Args() {
		if !hasPort.MatchString(server) {
			server += ":443"
		}

		var chain string

		conn, err := tls.Dial("tcp", server, nil)
		die.If(err)

		details := conn.ConnectionState()
		for _, cert := range details.PeerCertificates {
			p := pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}
			chain += string(pem.EncodeToMemory(&p))
		}

		fmt.Println(chain)
	}
}
