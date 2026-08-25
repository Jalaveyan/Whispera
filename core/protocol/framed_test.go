package protocol

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
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

func wireTestCert(tb testing.TB) tls.Certificate {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"example.com"},
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// A full record of ours has to land as exactly one TLS record. Hand the TLS
// layer one byte more than it can carry and it splits, and every full record
// arrives trailed by a runt — a shape no real TLS stream produces.
func TestFramedRecordsFillOneTLSRecord(t *testing.T) {
	cert := wireTestCert(t)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	sizes := make(chan []int, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			sizes <- nil
			return
		}
		s := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
		if err := s.HandshakeContext(context.Background()); err != nil {
			sizes <- nil
			return
		}
		var out []int
		hdr := make([]byte, 5)
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		for {
			if _, err := io.ReadFull(c, hdr); err != nil {
				break
			}
			n := int(binary.BigEndian.Uint16(hdr[3:5]))
			if _, err := io.CopyN(io.Discard, c, int64(n)); err != nil {
				break
			}
			out = append(out, 5+n)
		}
		sizes <- out
	}()

	raw, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cl := tls.Client(raw, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err := cl.HandshakeContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	fc := NewFramedConn(cl)
	go func() {
		_, _ = fc.Write(make([]byte, 4<<20))
		raw.Close()
	}()

	got := <-sizes
	// crypto/tls ramps record size up over the first ~128KB; only the steady
	// state says anything about our framing.
	const rampUp = 40
	if len(got) < rampUp+20 {
		t.Fatalf("only %d records observed, need the steady state", len(got))
	}
	steady := got[rampUp : len(got)-1]
	for i, n := range steady {
		if n != framedWireTarget {
			t.Fatalf("steady-state record %d is %d bytes, want %d: our records no longer line up with TLS records",
				i, n, framedWireTarget)
		}
	}
	t.Logf("%d steady-state records, all %d bytes", len(steady), framedWireTarget)
}
