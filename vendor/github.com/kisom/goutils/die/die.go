// Package die contains utilities for fatal error handling.
package die

import (
	"fmt"
	"os"
)

// If prints the error to stderr and exits if err != nil.
func If(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}
}

// With prints the message to stderr, appending a newline, and exits.
func With(fstr string, args ...interface{}) {
	out := fmt.Sprintf("[!] %s\n", fstr)
	fmt.Fprintf(os.Stderr, out, args...)
	os.Exit(1)
}

// When prints the error to stderr and exits if cond is true.
func When(cond bool, fstr string, args ...interface{}) {
	if cond {
		With(fstr, args...)
	}
}
