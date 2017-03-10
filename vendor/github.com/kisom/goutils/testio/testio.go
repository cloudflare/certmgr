// Package testio implements various io utility types. Included are
// BrokenWriter, which fails after writing a certain number of bytes;
// a BufCloser, which wraps a bytes.Buffer in a Close method; a
// BrokenReadWriter, which fails after writing a certain number of
// bytes and/or reading a certain number of bytes; a LoggingBuffer
// that logs all reads and writes; and a BufferConn, that is designed
// to simulate net.Conn.
package testio

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
)

// BrokenWriter implements an io.Writer that fails after a certain
// number of bytes. This can be used to simulate a network connection
// that breaks during write or a file on a filesystem that becomes
// full, for example. A BrokenWriter doesn't actually store any data.
type BrokenWriter struct {
	current, limit int
}

// NewBrokenWriter creates a new BrokenWriter that can store only
// limit bytes.
func NewBrokenWriter(limit int) *BrokenWriter {
	return &BrokenWriter{limit: limit}
}

// Write will write the byte slice to the BrokenWriter, failing if the
// maximum number of bytes has been reached.
func (w *BrokenWriter) Write(p []byte) (int, error) {
	if (len(p) + w.current) <= w.limit {
		w.current += len(p)
	} else {
		spill := (len(p) + w.current) - w.limit
		w.current = w.limit
		return len(p) - spill, errors.New("testio: write failed")
	}

	return len(p), nil
}

// Extend increases the byte limit to allow more data to be written.
func (w *BrokenWriter) Extend(n int) {
	w.limit += n
}

// Reset clears the limit and bytes in the BrokenWriter. Extend needs
// to be called to allow data to be written.
func (w *BrokenWriter) Reset() {
	w.limit = 0
	w.current = 0
}

// Close is provided to satisfy the Closer interface.
func (w *BrokenWriter) Close() error {
	w.Reset()
	return nil
}

// SilentBrokenWriter implements an io.Writer that fails after a
// certain number of bytes. However, this failure is silent: it just
// reports fewer bytes written than p.  It doesn't actually store any
// data, and is used to verify that io.Writer implementations properly
// return errors on short writes.
type SilentBrokenWriter struct {
	current, limit int
}

// NewSilentBrokenWriter creates a new SilentBrokenWriter that can store only
// limit bytes.
func NewSilentBrokenWriter(limit int) *SilentBrokenWriter {
	return &SilentBrokenWriter{limit: limit}
}

// Write will write the byte slice to the SilentBrokenWriter, failing if the
// maximum number of bytes has been reached.
func (w *SilentBrokenWriter) Write(p []byte) (int, error) {
	if (len(p) + w.current) <= w.limit {
		w.current += len(p)
	} else {
		spill := (len(p) + w.current) - w.limit
		w.current = w.limit
		return len(p) - spill, nil
	}

	return len(p), nil
}

// Extend increases the byte limit to allow more data to be written.
func (w *SilentBrokenWriter) Extend(n int) {
	w.limit += n
}

// Reset clears the limit and bytes in the SilentBrokenWriter. Extend needs
// to be called to allow data to be written.
func (w *SilentBrokenWriter) Reset() {
	w.limit = 0
	w.current = 0
}

// Close is provided to satisfy the Closer interface.
func (w *SilentBrokenWriter) Close() error {
	w.Reset()
	return nil
}

// BrokenReadWriter implements a broken reader and writer, backed by a
// bytes.Buffer.
type BrokenReadWriter struct {
	rlimit, wlimit int
	buf            *bytes.Buffer
}

// NewBrokenReadWriter initialises a new BrokerReadWriter with an empty
// reader and the specified limits.
func NewBrokenReadWriter(wlimit, rlimit int) *BrokenReadWriter {
	return &BrokenReadWriter{
		wlimit: wlimit,
		rlimit: rlimit,
		buf:    &bytes.Buffer{},
	}
}

// Write satisfies the Writer interface.
func (brw *BrokenReadWriter) Write(p []byte) (int, error) {
	if (len(p) + brw.buf.Len()) > brw.wlimit {
		remain := brw.wlimit - brw.buf.Len()
		if remain > 0 {
			brw.buf.Write(p[:remain])
			return remain, errors.New("testio: write failed")
		}
		return 0, errors.New("testio: write failed")
	}
	return brw.buf.Write(p)
}

// Read satisfies the Reader interface.
func (brw *BrokenReadWriter) Read(p []byte) (int, error) {
	remain := brw.rlimit - brw.buf.Len()
	if len(p) > remain {
		tmp := make([]byte, len(p)-remain)
		n, err := brw.buf.Read(tmp)
		if err == nil {
			err = io.EOF
		}
		copy(p, tmp)
		return n, err
	}
	return brw.buf.Read(p)
}

// Extend increases the BrokenReadWriter limit.
func (brw *BrokenReadWriter) Extend(w, r int) {
	brw.rlimit += r
	brw.wlimit += w
}

// Reset clears the internal buffer. It retains its original limit.
func (brw *BrokenReadWriter) Reset() {
	brw.buf.Reset()
}

// BufCloser is a buffer wrapped with a Close method.
type BufCloser struct {
	buf *bytes.Buffer
}

// Write writes the data to the BufCloser.
func (buf *BufCloser) Write(p []byte) (int, error) {
	return buf.buf.Write(p)
}

// Read reads data from the BufCloser.
func (buf *BufCloser) Read(p []byte) (int, error) {
	return buf.buf.Read(p)
}

// Close is a stub function to satisfy the io.Closer interface.
func (buf *BufCloser) Close() error {
	return nil
}

// Reset clears the internal buffer.
func (buf *BufCloser) Reset() {
	buf.buf.Reset()
}

// Bytes returns the contents of the buffer as a byte slice.
func (buf *BufCloser) Bytes() []byte {
	return buf.buf.Bytes()
}

// NewBufCloser creates and initializes a new BufCloser using buf as
// its initial contents. It is intended to prepare a BufCloser to read
// existing data. It can also be used to size the internal buffer for
// writing. To do that, buf should have the desired capacity but a
// length of zero.
func NewBufCloser(buf []byte) *BufCloser {
	bc := new(BufCloser)
	bc.buf = bytes.NewBuffer(buf)
	return bc
}

// NewBufCloserString creates and initializes a new Buffer using
// string s as its initial contents. It is intended to prepare a
// buffer to read an existing string.
func NewBufCloserString(s string) *BufCloser {
	buf := new(BufCloser)
	buf.buf = bytes.NewBufferString(s)
	return buf
}

// A LoggingBuffer is an io.ReadWriter that prints the hex value of
// the data for all reads and writes.
type LoggingBuffer struct {
	rw   io.ReadWriter
	w    io.Writer
	name string
}

// NewLoggingBuffer creates a logging buffer from an existing
// io.ReadWriter. By default, it will log to standard error.
func NewLoggingBuffer(rw io.ReadWriter) *LoggingBuffer {
	return &LoggingBuffer{
		rw: rw,
		w:  os.Stderr,
	}
}

// LogTo sets the io.Writer that the buffer will write logs to.
func (lb *LoggingBuffer) LogTo(w io.Writer) {
	lb.w = w
}

// SetName gives a name to the logging buffer to help distinguish
// output from this buffer.
func (lb *LoggingBuffer) SetName(name string) {
	lb.name = name
}

// Write writes the data to the logging buffer and writes the data to
// the logging writer.
func (lb *LoggingBuffer) Write(p []byte) (int, error) {
	if lb.name != "" {
		fmt.Fprintf(lb.w, "[%s] ", lb.name)
	}

	fmt.Fprintf(lb.w, "[WRITE] %x\n", p)
	return lb.rw.Write(p)
}

// Read reads the data from the logging buffer and writes the data to
// the logging writer.
func (lb *LoggingBuffer) Read(p []byte) (int, error) {
	n, err := lb.rw.Read(p)
	if err != nil {
		return n, err
	}
	if lb.name != "" {
		fmt.Fprintf(lb.w, "[%s] ", lb.name)
	}

	fmt.Fprintf(lb.w, "[READ] %x\n", p)
	return n, err
}

// BufferConn is a type that can be used to simulate network
// connections between a "client" (the code that uses the BufferConn)
// and some simulated "peer". Writes go to a "client" buffer, which is
// used to record the data sent by the caller, which may be read with
// ReadPeer. The peer's responses may be simulated by calling
// WritePeer; when the client reads from the BufferConn, they will see
// this data.
type BufferConn struct {
	client, peer *bytes.Buffer
}

// NewBufferConn initialises a new simulated network connection.
func NewBufferConn() *BufferConn {
	return &BufferConn{
		client: &bytes.Buffer{},
		peer:   &bytes.Buffer{},
	}
}

// Write writes to the client buffer.
func (bc *BufferConn) Write(p []byte) (int, error) {
	return bc.client.Write(p)
}

// Read reads from the peer buffer.
func (bc *BufferConn) Read(p []byte) (int, error) {
	return bc.peer.Read(p)
}

// WritePeer writes data to the peer buffer.
func (bc *BufferConn) WritePeer(p []byte) (int, error) {
	return bc.peer.Write(p)
}

// ReadClient reads data from the client buffer.
func (bc *BufferConn) ReadClient(p []byte) (int, error) {
	return bc.client.Read(p)
}

// Close is a dummy operation that allows the BufferConn to be used as
// an io.Closer.
func (bc *BufferConn) Close() error {
	return nil
}

// BrokenCloser is a BufCloser that fails to close.
type BrokenCloser struct {
	buf *bytes.Buffer
}

// Write writes the data to the BrokenCloser.
func (buf *BrokenCloser) Write(p []byte) (int, error) {
	return buf.buf.Write(p)
}

// Read reads data from the BrokenCloser.
func (buf *BrokenCloser) Read(p []byte) (int, error) {
	return buf.buf.Read(p)
}

// Close is a stub function to satisfy the io.Closer interface.
func (buf *BrokenCloser) Close() error {
	return errors.New("testio: broken closer is broken")
}

// Reset clears the internal buffer.
func (buf *BrokenCloser) Reset() {
	buf.buf.Reset()
}

// Bytes returns the contents of the buffer as a byte slice.
func (buf *BrokenCloser) Bytes() []byte {
	return buf.buf.Bytes()
}

// NewBrokenCloser creates and initializes a new BrokenCloser using buf as
// its initial contents. It is intended to prepare a BrokenCloser to read
// existing data. It can also be used to size the internal buffer for
// writing. To do that, buf should have the desired capacity but a
// length of zero.
func NewBrokenCloser(buf []byte) *BrokenCloser {
	bc := new(BrokenCloser)
	bc.buf = bytes.NewBuffer(buf)
	return bc
}

// NewBrokenCloserString creates and initializes a new Buffer using
// string s as its initial contents. It is intended to prepare a
// buffer to read an existing string.
func NewBrokenCloserString(s string) *BrokenCloser {
	buf := new(BrokenCloser)
	buf.buf = bytes.NewBufferString(s)
	return buf
}
