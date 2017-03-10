// showimp is a utility for displaying the imports in a package.
package main

import (
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/kisom/goutils/die"
	"github.com/kisom/goutils/logging"
)

var (
	gopath  string
	project string
	debug   bool
)

var (
	stdLibRegexp = regexp.MustCompile(`^\w+(/\w+)*$`)
	sourceRegexp = regexp.MustCompile(`^[^.].*\.go$`)
	log          = logging.NewConsole()
	imports      = map[string]bool{}
	fset         = &token.FileSet{}
)

func debugf(format string, args ...interface{}) {
	if debug {
		fmt.Printf(format, args...)
	}
}

func debugln(args ...interface{}) {
	if debug {
		fmt.Println(args...)
	}
}

func init() {
	gopath = os.Getenv("GOPATH")
	if gopath == "" {
		fmt.Fprintf(os.Stderr, "GOPATH isn't set, can't proceed.")
		os.Exit(1)
	}
	gopath += "/src/"

	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to establish working directory: %v", err)
		os.Exit(1)
	}

	if !strings.HasPrefix(wd, gopath) {
		fmt.Fprintf(os.Stderr, "Can't determine my location in the GOPATH.\n")
		fmt.Fprintf(os.Stderr, "Working directory is %s\n", wd)
		fmt.Fprintf(os.Stderr, "Go source path is %s\n", gopath)
		os.Exit(1)
	}

	project = wd[len(gopath):]
}

func walkFile(path string, info os.FileInfo, err error) error {
	if !sourceRegexp.MatchString(path) {
		return nil
	}

	debugln(path)

	f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
	if err != nil {
		return err
	}

	for _, importSpec := range f.Imports {
		importPath := strings.Trim(importSpec.Path.Value, `"`)
		if stdLibRegexp.MatchString(importPath) {
			debugln("standard lib:", importPath)
			continue
		} else if strings.HasPrefix(importPath, project) {
			debugln("internal import:", importPath)
			continue
		} else if strings.HasPrefix(importPath, "golang.org/") {
			debugln("extended lib:", importPath)
			continue
		}
		debugln("import:", importPath)
		imports[importPath] = true
	}

	return nil
}

func main() {
	flag.BoolVar(&debug, "v", false, "log debugging information")
	flag.Parse()

	err := filepath.Walk(".", walkFile)
	die.If(err)

	fmt.Println("External imports:")
	importList := make([]string, 0, len(imports))
	for imp := range imports {
		importList = append(importList, imp)
	}
	sort.Strings(importList)

	for _, imp := range importList {
		fmt.Println("\t", imp)
	}
}
