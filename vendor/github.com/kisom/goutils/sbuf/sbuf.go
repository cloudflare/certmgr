// Package sbuf implements a byte buffer that can be wiped. The underlying
// byte slice is wiped on read before being declaimed, and when the
// buffer is closed, its storage is zeroised.
package sbuf

import "io"

func zero(in []byte, n int) {
	if in == nil {
		return
	}

	stop := n
	if stop > len(in) || stop == 0 {
		stop = len(in)
	}

	for i := 0; i < stop; i++ {
		in[i] ^= in[i]
	}
}

// A Buffer is a variable-sized buffer of bytes with Read and Write
// methods. The zero value for Buffer is an empty buffer ready to use.
type Buffer struct {
	buf []byte
}

// NewBuffer creates a new buffer with the specified capacity.
func NewBuffer(n int) *Buffer {
	return &Buffer{
		buf: make([]byte, 0, n),
	}
}

// NewBufferFrom creates a new buffer from the byte slice passed in. The
// original data will be wiped.
func NewBufferFrom(p []byte) *Buffer {
	buf := NewBuffer(len(p))
	buf.Write(p)
	zero(p, len(p))
	return buf
}

// Read reads the next len(p) bytes from the buffer or until the buffer
// is drained. The return value n is the number of bytes read. If the
// buffer has no data to return, err is io.EOF (unless len(p) is zero);
// otherwise it is nil.
func (buf *Buffer) Read(p []byte) (int, error) {
	if len(buf.buf) == 0 {
		if len(p) == 0 {
			return 0, nil
		}
		return 0, io.EOF
	}

	copyLength := len(p)
	if copyLength > len(buf.buf) {
		copyLength = len(buf.buf)
	}

	copy(p, buf.buf)
	zero(buf.buf, len(p))
	buf.buf = buf.buf[copyLength:]
	return copyLength, nil
}

// ReadByte reads the next byte from the buffer. If the buffer has no
// data to return, err is io.EOF; otherwise it is nil.
func (buf *Buffer) ReadByte() (byte, error) {
	if len(buf.buf) == 0 {
		return 0, io.EOF
	}

	c := buf.buf[0]
	buf.buf[0] = 0
	buf.buf = buf.buf[1:]
	return c, nil
}

func (buf *Buffer) grow(n int) {
	tmp := make([]byte, len(buf.buf), len(buf.buf)+n)
	copy(tmp, buf.buf)
	zero(buf.buf, len(buf.buf))
	buf.buf = tmp
}

// Write appends the contents of p to the buffer, growing the buffer
// as needed. The return value n is the length of p; err is always nil.
func (buf *Buffer) Write(p []byte) (int, error) {
	r := len(buf.buf) + len(p)
	if cap(buf.buf) < r {
		l := r
		for {
			if l > r {
				break
			}
			l *= 2
		}
		buf.grow(l - cap(buf.buf))
	}
	buf.buf = append(buf.buf, p...)
	return len(p), nil
}

// WriteByte adds the byte c to the buffer, growing the buffer as needed.
func (buf *Buffer) WriteByte(c byte) error {
	r := len(buf.buf) + 1
	if cap(buf.buf) < r {
		l := r * 2
		buf.grow(l - cap(buf.buf))
	}
	buf.buf = append(buf.buf, c)
	return nil
}

// Close destroys and zeroises the buffer. The buffer will be re-opened
// on the next write.
func (buf *Buffer) Close() {
	zero(buf.buf, len(buf.buf))
	buf.buf = nil
}

// Len returns the length of the buffer.
func (buf *Buffer) Len() int {
	return len(buf.buf)
}

// Cap returns the capacity of the buffer.
func (buf *Buffer) Cap() int {
	return cap(buf.buf)
}

// Bytes returns the bytes currently in the buffer, and closes itself.
func (buf *Buffer) Bytes() []byte {
	if buf.buf == nil {
		return nil
	}

	p := make([]byte, buf.Len())
	buf.Read(p)
	buf.Close()
	return p
}
