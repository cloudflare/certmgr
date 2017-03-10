// Package mwc implements MultiWriteClosers.
package mwc

import "io"

type mwc struct {
	wcs []io.WriteCloser
}

// Write implements the Writer interface.
func (t *mwc) Write(p []byte) (n int, err error) {
	for _, w := range t.wcs {
		n, err = w.Write(p)
		if err != nil {
			return
		}
		if n != len(p) {
			err = io.ErrShortWrite
			return
		}
	}
	return len(p), nil
}

// Close implements the Closer interface.
func (t *mwc) Close() error {
	for _, wc := range t.wcs {
		err := wc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// MultiWriteCloser creates a WriteCloser that duplicates its writes to
// all the provided writers, similar to the Unix tee(1) command.
func MultiWriteCloser(wc ...io.WriteCloser) io.WriteCloser {
	wcs := make([]io.WriteCloser, len(wc))
	copy(wcs, wc)
	return &mwc{wcs}
}
