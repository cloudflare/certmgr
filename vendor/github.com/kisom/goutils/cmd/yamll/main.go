package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v2"
)

type empty struct{}

func errorf(format string, args ...interface{}) {
	format += "\n"
	fmt.Fprintf(os.Stderr, format, args...)
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `Usage: yamll [-hq] files...

	For each file, yamll will make sure it is a well-formatted YAML
	file.  Unless the -q option is passed, yamll will print the names
	of each file and whether it was well-formed. With the -q option,
	only malformed files are printed.
`)
}

func init() {
	flag.Usage = func() { usage(os.Stderr); os.Exit(1) }
}

func main() {
	help := flag.Bool("h", false, "Print program usage.")
	quiet := flag.Bool("q", false,
		"Quiet mode - don't note well-formed files, only malformed ones.")
	flag.Parse()

	if *help {
		usage(os.Stdout)
		os.Exit(0)
	}

	if flag.NArg() == 1 && flag.Arg(0) == "-" {
		path := "stdin"
		in, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			errorf("%s FAILED: %s", path, err)
			os.Exit(1)
		}

		var e empty
		err = yaml.Unmarshal(in, &e)
		if err != nil {
			errorf("%s FAILED: %s", path, err)
			os.Exit(1)
		}

		if !*quiet {
			fmt.Printf("%s: OK\n", path)
		}

		os.Exit(0)
	}

	for _, path := range flag.Args() {
		in, err := ioutil.ReadFile(path)
		if err != nil {
			errorf("%s FAILED: %s", path, err)
			continue
		}

		var e empty
		err = yaml.Unmarshal(in, &e)
		if err != nil {
			errorf("%s FAILED: %s", path, err)
			continue
		}

		if !*quiet {
			fmt.Printf("%s: OK\n", path)
		}
	}
}
