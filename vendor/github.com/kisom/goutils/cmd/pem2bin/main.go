package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

var ext = ".bin"

func stripPEM(path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	p, rest := pem.Decode(data)
	if len(rest) != 0 {
		fmt.Fprintf(os.Stderr, "[WARNING] extra data in PEM file\n")
		fmt.Fprintf(os.Stderr, "          (only the first object will be decoded)\n")
	}

	return ioutil.WriteFile(path+ext, p.Bytes, 0644)
}

func main() {
	flag.Parse()

	for _, path := range flag.Args() {
		err := stripPEM(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "processing %s failed: %v\n", path, err)
		} else {
			fmt.Println(path, "->", path+ext)
		}
	}
}
