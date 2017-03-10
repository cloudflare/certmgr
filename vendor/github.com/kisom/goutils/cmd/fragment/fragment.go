package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/kisom/goutils/die"
)

func usage() {
	progname := filepath.Base(os.Args[0])
	fmt.Printf(`Usage: %s [-nl] file start [end]

	Print a fragment of a file starting a line 'start' and ending
	at line 'end', or EOF if no end is specified.

	The -nl flag will suppress printing of line numbers.
`, progname)
}

func main() {
	quiet := flag.Bool("nl", false, "No line-numbering.")
	flag.Parse()

	if flag.NArg() < 2 || flag.NArg() > 3 {
		usage()
		os.Exit(1)
	}

	start, err := strconv.Atoi(flag.Arg(1))
	die.If(err)

	var end int
	var offset bool
	if flag.NArg() == 3 {
		endStr := flag.Arg(2)
		if endStr[0] == '+' {
			offset = true
			endStr = endStr[1:]
		}
		end, err = strconv.Atoi(endStr)
		die.If(err)
		if offset {
			end += start
		}
	}

	file, err := os.Open(flag.Arg(0))
	die.If(err)
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// initial empty line to start numbering at 1.
	var lines = make([]string, 1)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if end == 0 {
		end = len(lines) - 1
	}

	if end < start {
		fmt.Fprintln(os.Stderr, "[!] end < start, swapping values")
		tmp := end
		end = start
		start = tmp
	}

	var fmtStr string

	if !*quiet {
		maxLine := fmt.Sprintf("%d", len(lines))
		fmtStr = fmt.Sprintf("%%0%dd: %%s", len(maxLine))
	}

	endFunc := func(n int) bool {
		if n == 0 {
			return false
		}

		if n > end {
			return true
		}
		return false
	}

	fmtStr += "\n"
	for i := start; !endFunc(i); i++ {
		if *quiet {
			fmt.Println(lines[i])
		} else {
			fmt.Printf(fmtStr, i, lines[i])
		}
	}
}
