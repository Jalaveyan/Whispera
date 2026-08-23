package protocol

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func framedPair(t *testing.T) (*FramedConn, *FramedConn, func()) {
	t.Helper()
	a, b := net.Pipe()
	return NewFramedConn(a), NewFramedConn(b), func() { a.Close(); b.Close() }
}

func TestFramedRoundTrip(t *testing.T) {
	cl, srv, done := framedPair(t)
	defer done()

	payload := []byte("данные одного потока")
	go func() {
		_, _ = cl.Write(payload)
		_ = cl.EndStream()
	}()

	got, err := io.ReadAll(srv)
	if err != nil {
		t.Fatalf("чтение: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("получено %q, ожидалось %q", got, payload)
	}
	if !srv.StreamDone() {
		t.Fatal("маркер конца не распознан")
	}
}

func TestFramedSplitsLargeWrites(t *testing.T) {
	cl, srv, done := framedPair(t)
	defer done()

	payload := bytes.Repeat([]byte("x"), framedMaxData*2+123)
	go func() {
		_, _ = cl.Write(payload)
		_ = cl.EndStream()
	}()

	got, err := io.ReadAll(srv)
	if err != nil {
		t.Fatalf("чтение: %v", err)
	}
	if len(got) != len(payload) {
		t.Fatalf("получено %d байт, ожидалось %d", len(got), len(payload))
	}
}

func TestFramedCarriesTwoStreamsOverOneConn(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	cl, srv := NewFramedConn(a), NewFramedConn(b)

	go func() {
		_, _ = cl.Write([]byte("первый"))
		_ = cl.EndStream()
		cl.Reset()
		_, _ = cl.Write([]byte("второй"))
		_ = cl.EndStream()
	}()

	first, err := io.ReadAll(srv)
	if err != nil || string(first) != "первый" {
		t.Fatalf("первый поток: %q, %v", first, err)
	}
	if !srv.Reusable() && !srv.StreamDone() {
		t.Fatal("после маркера соединение должно считаться свободным")
	}
	srv.Reset()

	second, err := io.ReadAll(srv)
	if err != nil || string(second) != "второй" {
		t.Fatalf("второй поток: %q, %v", second, err)
	}
}

func TestFramedRejectsGarbage(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	go func() {
		_ = a.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = a.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x05, 0, 0, 0, 0, 0})
	}()

	srv := NewFramedConn(b)
	buf := make([]byte, 16)
	if _, err := srv.Read(buf); err == nil {
		t.Fatal("запись не того типа должна отвергаться")
	}
}
