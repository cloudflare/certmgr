package testio

import (
	"bytes"
	"os"
	"testing"
)

func TestBrokenWriter(t *testing.T) {
	buf := NewBrokenWriter(2)
	data := []byte{1, 2}

	n, err := buf.Write(data)
	if err != nil {
		t.Fatalf("%v", err)
	} else if n != 2 {
		t.Fatalf("expected write size of 2, have %d", n)
	}

	_, err = buf.Write(data)
	if err == nil {
		t.Fatal("expected a write failure")
	}

	buf.Reset()
	_, err = buf.Write(data)
	if err == nil {
		t.Fatalf("expected a write failure after reset")
	}

	buf.Extend(2)
	_, err = buf.Write(data)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestBufCloser(t *testing.T) {
	var data = []byte{1, 2}
	var read = make([]byte, 2)

	buf := NewBufCloser(data)
	_, err := buf.Read(read)
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = buf.Write(data)
	if err != nil {
		t.Fatalf("%v", err)
	}

	buf.Close()
	buf.Reset()

	s := "hi"
	buf = NewBufCloserString(s)

	read = buf.Bytes()
	if string(read) != s {
		t.Fatalf("expected %s, have %s", s, read)
	}
}

func TestLoggingBuffer(t *testing.T) {
	src := &bytes.Buffer{}
	data := []byte("AB")
	lb := NewLoggingBuffer(src)
	_, err := lb.Write(data)
	if err != nil {
		t.Fatalf("%v", err)
	}

	src.Reset()
	lb.SetName("TEST")
	out := &bytes.Buffer{}
	lb.LogTo(out)

	_, err = lb.Write(data)
	if err != nil {
		t.Fatalf("%v", err)
	}

	expected := "[TEST] [WRITE] 4142\n"
	if string(out.Bytes()) != expected {
		t.Fatalf("expected '%s', have '%s'", expected, string(out.Bytes()))
	}

	out.Reset()
	src = bytes.NewBuffer(data)
	read := make([]byte, 2)

	_, err = lb.Read(read)
	if err != nil {
		t.Fatalf("%v", err)
	}

	expected = "[TEST] [READ] 4142\n"
	if string(out.Bytes()) != expected {
		t.Fatalf("expected '%s', have '%s'", expected, string(out.Bytes()))
	}

	out.Reset()
	lb.SetName("")
	lb.LogTo(os.Stderr)
	lb.Write([]byte("AB"))

	lb.LogTo(out)
	_, err = lb.Read(read)
	if err != nil {
		t.Fatalf("%v", err)
	}

	expected = "[READ] 4142\n"
	if string(out.Bytes()) != expected {
		t.Fatalf("expected '%s', have '%s'", expected, string(out.Bytes()))
	}

	src.Reset()
	_, err = lb.Read(read)
	if err == nil {
		t.Fatal("expected a read failure")
	}
}

func TestBrokenReadWriter(t *testing.T) {
	brw := NewBrokenReadWriter(0, 0)
	lb := NewLoggingBuffer(brw)

	var p = make([]byte, 2)
	var data = []byte("HI")
	_, err := lb.Write(data)
	if err == nil {
		t.Fatal("expected a write failure")
	}

	_, err = lb.Read(p)
	if err == nil {
		t.Fatal("expected a read failure")
	}

	brw.Extend(1, 0)
	_, err = lb.Write(data)
	if err == nil {
		t.Fatal("expected a write failure")
	}

	brw.Extend(2, 0)
	_, err = lb.Write(data)
	if err != nil {
		t.Fatalf("%v", err)
	}

	brw.Extend(4, 1)
	_, err = lb.Write(data)
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = lb.Read(p)
	if err == nil {
		t.Fatal("expected a read failure")
	}

	brw.Reset()
	brw.Extend(10, 2)
	_, err = lb.Write(data)
	if err != nil {
		t.Fatalf("%v", err)
	}

	p = make([]byte, 1)
	_, err = lb.Read(p)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestBufferConn(t *testing.T) {
	bc := NewBufferConn()

	client := []byte("AB")
	peer := []byte("XY")

	_, err := bc.WritePeer(peer)
	if err != nil {
		t.Fatalf("%v", err)
	}

	var p = make([]byte, 2)
	_, err = bc.Write(client)
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = bc.Read(p)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(p, peer) {
		t.Fatalf("client should have read %x, but read %x",
			peer, p)
	}

	_, err = bc.ReadClient(p)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(client, p) {
		t.Fatalf("client should have sent %x, but sent %x",
			client, p)
	}

	err = bc.Close()
	if err != nil {
		t.Fatalf("Close should always return nil, but it returned %v", err)
	}
}
