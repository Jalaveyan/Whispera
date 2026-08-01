package socks5

import (
	"bytes"
	"io"
	"testing"
)

func TestCollectPeekTransparent(t *testing.T) {
	var got []byte
	CollectHook = func(b []byte) { got = b }
	defer func() { CollectHook = nil }()
	lastCollect.Store(0)

	body := make([]byte, 50)
	body[0] = 0x01
	rec := append([]byte{0x16, 0x03, 0x01, 0x00, byte(len(body))}, body...)

	r := &collectPeekReader{Reader: bytes.NewReader(rec)}
	out := make([]byte, len(rec))
	n, err := io.ReadFull(r, out)
	if err != nil || n != len(rec) || !bytes.Equal(out, rec) {
		t.Fatalf("data not passed through unchanged: n=%d err=%v", n, err)
	}
	if len(got) != 5+len(body) {
		t.Fatalf("hook not called with full record, got %d", len(got))
	}
}

func TestCollectPeekNonTLS(t *testing.T) {
	called := false
	CollectHook = func(b []byte) { called = true }
	defer func() { CollectHook = nil }()
	lastCollect.Store(0)

	plain := []byte("GET / HTTP/1.1\r\n\r\n")
	r := &collectPeekReader{Reader: bytes.NewReader(plain)}
	out, _ := io.ReadAll(r)
	if !bytes.Equal(out, plain) {
		t.Fatalf("non-TLS data altered")
	}
	if called {
		t.Fatalf("hook fired on non-TLS data")
	}
}
