package mux

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

type padTestConn struct {
	buf bytes.Buffer
}

func (c *padTestConn) Read(p []byte) (int, error)         { return c.buf.Read(p) }
func (c *padTestConn) Write(p []byte) (int, error)        { return c.buf.Write(p) }
func (c *padTestConn) Close() error                       { return nil }
func (c *padTestConn) LocalAddr() net.Addr                { return nil }
func (c *padTestConn) RemoteAddr() net.Addr               { return nil }
func (c *padTestConn) SetDeadline(t time.Time) error      { return nil }
func (c *padTestConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *padTestConn) SetWriteDeadline(t time.Time) error { return nil }

func readExactly(t *testing.T, pc *PaddedConn, n int) []byte {
	t.Helper()
	out := make([]byte, 0, n)
	tmp := make([]byte, 4096)
	for len(out) < n {
		m, err := pc.Read(tmp)
		if m > 0 {
			out = append(out, tmp[:m]...)
		}
		if err != nil {
			t.Fatalf("Read err after %d/%d bytes: %v", len(out), n, err)
		}
	}
	return out
}

func TestPaddedConn_RoundTripSmall(t *testing.T) {
	pc := NewPaddedConn(&padTestConn{}, 128)
	payload := []byte("hello world")
	if _, err := pc.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := readExactly(t, pc, len(payload))
	if !bytes.Equal(got, payload) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, payload)
	}
}

func TestPaddedConn_RoundTripLargeChunked(t *testing.T) {
	pc := NewPaddedConn(&padTestConn{}, 128)
	payload := make([]byte, 200000)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	if _, err := pc.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := readExactly(t, pc, len(payload))
	if !bytes.Equal(got, payload) {
		t.Fatalf("large round-trip mismatch (len got=%d want=%d)", len(got), len(payload))
	}
}

func TestPaddedConn_OverflowClampNoDesync(t *testing.T) {
	conn := &padTestConn{}
	pc := NewPaddedConn(conn, 60000)
	payload := make([]byte, 65000)
	for i := range payload {
		payload[i] = byte(i)
	}
	if _, err := pc.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}

	frame := conn.buf.Bytes()
	if len(frame) < 4 {
		t.Fatalf("frame too short: %d", len(frame))
	}
	totalLen := int(binary.BigEndian.Uint16(frame[0:2]))
	dataLen := int(binary.BigEndian.Uint16(frame[2:4]))
	if dataLen != len(payload) {
		t.Fatalf("dataLen header=%d, want %d (overflow corrupted it)", dataLen, len(payload))
	}
	if len(frame) != 2+totalLen {
		t.Fatalf("frame self-inconsistent: on-wire=%d, header totalLen=%d (want on-wire=2+totalLen)", len(frame), totalLen)
	}

	got := readExactly(t, pc, len(payload))
	if !bytes.Equal(got, payload) {
		t.Fatalf("overflow-region round-trip mismatch")
	}
}

func TestPaddedConn_PaddingIsContinuousNotBucketed(t *testing.T) {
	conn := &padTestConn{}
	pc := NewPaddedConn(conn, 128)

	payload := []byte("0123456789")
	sizes := make(map[int]bool)
	min, max := -1, -1
	for i := 0; i < 64; i++ {
		conn.buf.Reset()
		if _, err := pc.Write(payload); err != nil {
			t.Fatalf("Write: %v", err)
		}
		onWire := conn.buf.Len()
		sizes[onWire] = true
		if min == -1 || onWire < min {
			min = onWire
		}
		if onWire > max {
			max = onWire
		}
	}
	if len(sizes) < 8 {
		t.Fatalf("on-wire sizes too clustered: only %d distinct values across 64 writes (%v)", len(sizes), sizes)
	}
	if max-min < 16 {
		t.Fatalf("on-wire size spread too narrow: min=%d max=%d", min, max)
	}
}

func TestPaddedConn_RejectsBadFrameLen(t *testing.T) {
	conn := &padTestConn{}
	conn.buf.Write([]byte{0x00, 0x01})
	pc := NewPaddedConn(conn, 128)
	if _, err := pc.Read(make([]byte, 16)); err == nil {
		t.Fatalf("expected error on totalLen=1, got nil")
	}
}

func TestPaddedConn_RejectsDataLenExceedingFrame(t *testing.T) {
	conn := &padTestConn{}
	conn.buf.Write([]byte{0x00, 0x0A, 0x00, 0x14})
	conn.buf.Write(make([]byte, 8))
	pc := NewPaddedConn(conn, 128)
	if _, err := pc.Read(make([]byte, 64)); err == nil {
		t.Fatalf("expected error on dataLen>frame, got nil")
	}
}

func TestPaddedConn_SkipsZeroDataFrame(t *testing.T) {
	conn := &padTestConn{}
	conn.buf.Write([]byte{0x00, 0x02, 0x00, 0x00})
	conn.buf.Write([]byte{0x00, 0x07, 0x00, 0x05})
	conn.buf.Write([]byte("world"))
	pc := NewPaddedConn(conn, 128)
	tmp := make([]byte, 64)
	n, err := pc.Read(tmp)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(tmp[:n]) != "world" {
		t.Fatalf("got %q, want %q (zero-data frame not skipped?)", tmp[:n], "world")
	}
}

func TestResumeToken(t *testing.T) {
	key := []byte("session-key-000000000000000000000")
	nonce := []byte("nonce-1234567890")

	if !bytes.Equal(ResumeToken(key, nonce, 1), ResumeToken(key, nonce, 1)) {
		t.Fatal("ResumeToken not deterministic")
	}
	if bytes.Equal(ResumeToken(key, nonce, 1), ResumeToken(key, nonce, 2)) {
		t.Fatal("ResumeToken did not roll between counters")
	}
	other := []byte("other-nonce-4567")
	if bytes.Equal(ResumeToken(key, nonce, 1), ResumeToken(key, other, 1)) {
		t.Fatal("ResumeToken did not depend on nonce")
	}
	if len(ResumeToken(key, nonce, 1)) != resumeTokenLen {
		t.Fatalf("token len = %d, want %d", len(ResumeToken(key, nonce, 1)), resumeTokenLen)
	}
}

func TestResumeHeaderRoundTrip(t *testing.T) {
	tok := ResumeToken([]byte("k"), []byte("n"), 3)
	var buf bytes.Buffer
	if err := WriteResumeHeader(&buf, ResumeResume, tok); err != nil {
		t.Fatal(err)
	}
	typ, payload, err := ReadResumeHeader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if typ != ResumeResume {
		t.Fatalf("type = %d, want %d", typ, ResumeResume)
	}
	if !bytes.Equal(payload, tok) {
		t.Fatal("payload roundtrip mismatch")
	}
}
