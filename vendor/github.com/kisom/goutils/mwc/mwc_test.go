package mwc

import (
	"bytes"
	"testing"

	"github.com/kisom/goutils/testio"
	"github.com/kisom/goutils/assert"
)

func TestMWC(t *testing.T) {
	buf1 := testio.NewBufCloser(nil)
	buf2 := testio.NewBufCloser(nil)

	mwc := MultiWriteCloser(buf1, buf2)

	_, err := mwc.Write([]byte("hello, world"))
	assert.NoErrorT(t, err)

	assert.BoolT(t, bytes.Equal(buf1.Bytes(), buf2.Bytes()), "write failed")
	assert.BoolT(t, bytes.Equal(buf1.Bytes(), []byte("hello, world")), "write failed")

	err = mwc.Close()
	assert.NoErrorT(t, err)
}

func TestMWCShort(t *testing.T) {
	buf1 := testio.NewBufCloser(nil)
	buf2 := testio.NewBufCloser(nil)
	buf3 := testio.NewBrokenWriter(5)
	buf4 := testio.NewSilentBrokenWriter(5)

	mwc := MultiWriteCloser(buf1, buf2, buf3)
	defer mwc.Close()

	_, err := mwc.Write([]byte("hello, world"))
	assert.ErrorT(t, err, "expected a short write error", "but no error occurred")
	mwc.Close()

	mwc = MultiWriteCloser(buf1, buf2, buf4)
	_, err = mwc.Write([]byte("hello, world"))
	assert.ErrorT(t, err, "expected a short write error", "but no error occurred")			
}

func TestMWCClose(t *testing.T) {
	buf1 := testio.NewBufCloser(nil)
	buf2 := testio.NewBufCloser(nil)
	buf3 := testio.NewBrokenCloser(nil)

	mwc := MultiWriteCloser(buf1, buf2, buf3)
	_, err := mwc.Write([]byte("hello, world"))
	assert.NoErrorT(t, err)

	err = mwc.Close()
	assert.ErrorT(t, err, "expected broken closer to fail")
}
