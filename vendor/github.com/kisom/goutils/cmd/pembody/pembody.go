package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/kisom/goutils/lib"
)

func main() {
	flag.Parse()
	if flag.NArg() != 1 {
		lib.Errx(lib.ExitFailure, "a single filename is required")
	}

	var in []byte
	var err error

	path := flag.Arg(0)
	if path == "-" {
		in, err = ioutil.ReadAll(os.Stdin)
	} else {
		in, err = ioutil.ReadFile(flag.Arg(0))
	}
	if err != nil {
		lib.Err(lib.ExitFailure, err, "couldn't read file")
	}

	p, _ := pem.Decode(in)
	if p == nil {
		lib.Errx(lib.ExitFailure, "%s isn't a PEM-encoded file", flag.Arg(0))
	}
	fmt.Printf("%s", p.Bytes)
}
