package main

import (
	"bytes"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/kisom/goutils/assert"
	"github.com/kisom/goutils/die"
	"github.com/kisom/goutils/lib"
)

func usage(w io.Writer) {
	fmt.Fprintf(w, `Usage: %s [-h] -t type sources

	Flags:
		-h	Display this help message.
		-t type	Set the PEM type. This is required.

	Sources may be a list of files or a single '-'. A single dash
	(or no arguments) will cause %s to use standard input.
`, lib.ProgName(), lib.ProgName())
}

func init() {
	flag.Usage = func() { usage(os.Stderr) }
}

func copyFile(path string, buf *bytes.Buffer) error {
	assert.Bool(buf != nil, "buffer should not be nil")
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	_, err = io.Copy(buf, file)
	file.Close()
	return err
}

func main() {
	var pemType string
	flag.StringVar(&pemType, "t", "", "Specify the `PEM type`.")
	flag.Parse()

	die.When(len(pemType) == 0, "no PEM type specified.")

	buf := &bytes.Buffer{}
	argc := flag.NArg()
	var err error

	switch {
	case argc == 0:
		_, err = io.Copy(buf, os.Stdin)
		if err != nil {
			lib.Err(lib.ExitFailure, err, "failed to read input")
		}
	case argc == 1:
		path := flag.Arg(0)
		if path == "-" {
			_, err = io.Copy(buf, os.Stdin)
		} else {
			err = copyFile(path, buf)
		}

		if err != nil {
			lib.Err(lib.ExitFailure, err, "failed to read input")
		}
	case argc > 1:
		for i := 0; i < argc; i++ {
			path := flag.Arg(i)
			err = copyFile(path, buf)
			if err != nil {
				lib.Err(lib.ExitFailure, err, "reading file failed")
			}
		}
	default:
		panic("shouldn't be here")
	}

	p := &pem.Block{
		Type:  pemType,
		Bytes: buf.Bytes(),
	}

	encoded := string(pem.EncodeToMemory(p))
	fmt.Print(encoded)
}
