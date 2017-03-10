package main

import (
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kisom/goutils/fileutil"
	"github.com/kisom/goutils/lib"
)

func hashName(path, encodedHash string) string {
	basename := filepath.Base(path)
	location := filepath.Dir(path)
	ext := filepath.Ext(basename)
	return filepath.Join(location, encodedHash+ext)
}

func newName(path string) (string, error) {
	h := fnv.New32a()

	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	_, err = io.Copy(h, f)
	if err != nil {
		return "", err
	}

	var buf [8]byte
	binary.BigEndian.PutUint32(buf[:], h.Sum32())
	encodedHash := base32.StdEncoding.EncodeToString(h.Sum(nil))
	encodedHash = strings.TrimRight(encodedHash, "=")
	return hashName(path, encodedHash), nil
}

func move(dst, src string, force bool) (err error) {
	if fileutil.FileDoesExist(dst) && !force {
		return fmt.Errorf("%s exists (pass the -f flag to overwrite)", dst)
		return nil
	}
	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}

	defer func(e error) {
		dstFile.Close()
		if e != nil {
			os.Remove(dst)
		}
	}(err)

	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return err
	}

	os.Remove(src)
	return nil
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `Usage: renfnv [-fhlnv] files...

renfnv renames files to the base32-encoded 32-bit FNV-1a hash of their
contents, preserving the dirname and extension.

Options:
	-f	force overwriting of files when there is a collision.
	-h	print this help message.
	-l	list changed files.
	-n	Perform a dry run: don't actually move files.
	-v	Print all files as they are processed. If both -v and -l
		are specified, it will behave as if only -v was specified.
`)
}

func init() {
	flag.Usage = func () { usage(os.Stdout) }
}

func main() {
	var dryRun, force, printChanged, verbose bool
	flag.BoolVar(&force, "f", false, "force overwriting of files if there is a collision")
	flag.BoolVar(&printChanged, "l", false, "list changed files")
	flag.BoolVar(&dryRun, "n", false, "dry run --- don't perform moves")
	flag.BoolVar(&verbose, "v", false, "list all processed files")

	flag.Parse()

	if verbose && printChanged {
		printChanged = false
	}

	for _, file := range flag.Args() {
		renamed, err := newName(file)
		if err != nil {
			lib.Warn(err, "failed to get new file name")
			continue
		}

		if verbose && !printChanged {
			fmt.Println(file)
		}

		if renamed != file {
			if !dryRun {
				err = move(renamed, file, force)
				if err != nil {
					lib.Warn(err, "failed to rename file from %s to %s", file, renamed)
					continue
				}
			}

			if printChanged && !verbose {
				fmt.Println(file, "->", renamed)
			}
		}
	}
}
