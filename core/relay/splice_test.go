package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/nekoskin/whispera/common/buf"
	"github.com/nekoskin/whispera/core/protocol"
)

const switchMarker = 0xFFFF

func decodeSwitchStream(t *testing.T, r io.Reader) (data []byte, switched bool) {
	t.Helper()
	for {
		var hdr [5]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return data, false
		}
		if hdr[0] != 0x17 {
			t.Fatalf("bad record type 0x%02x", hdr[0])
		}
		body := int(binary.BigEndian.Uint16(hdr[3:5]))
		rec := make([]byte, body)
		if _, err := io.ReadFull(r, rec); err != nil {
			t.Fatalf("read record body: %v", err)
		}
		dataLen := int(binary.BigEndian.Uint16(rec[0:2]))
		if dataLen == switchMarker {
			rest, _ := io.ReadAll(r)
			return append(data, rest...), true
		}
		if dataLen == 0 {
			return data, false
		}
		data = append(data, rec[2:2+dataLen]...)
	}
}

func runSpliceFrom(t *testing.T, payload []byte, left int64) (got []byte, switched bool, sc *serverSpliceConn) {
	t.Helper()
	wireA, wireB := net.Pipe()
	srcA, srcB := net.Pipe()
	sc = &serverSpliceConn{Conn: wireA, up: protocol.NewFramedConn(wireA, protocol.NewShapeBudget()), down: protocol.NewFramedConn(wireA, protocol.NewShapeBudget()), raw: wireA, left: left}

	go func() {
		_, _ = srcB.Write(payload)
		_ = srcB.Close()
	}()
	go func() {
		_, _ = sc.spliceFrom(srcA)
		_ = sc.down.EndStream()
		_ = wireA.Close()
	}()

	got, switched = decodeSwitchStream(t, wireB)
	return got, switched, sc
}

func TestServerSpliceShortStreamStaysFramed(t *testing.T) {
	payload := bytes.Repeat([]byte("0123456789abcdef"), 500)

	got, switched, sc := runSpliceFrom(t, payload, spliceAfterBytes)

	if switched {
		t.Error("stream under the threshold dropped out of framing; the connection cannot be pooled after that")
	}
	if sc.down.SwitchedRaw() {
		t.Error("SwitchedRaw() = true for a stream under the threshold")
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

func TestServerSpliceBulkSwitchesToRaw(t *testing.T) {
	payload := bytes.Repeat([]byte("0123456789abcdef"), 5000)

	got, switched, sc := runSpliceFrom(t, payload, 1024)

	if !switched {
		t.Error("stream past the threshold kept framing; bulk never reaches the kernel path")
	}
	if !sc.down.SwitchedRaw() {
		t.Error("SwitchedRaw() = false after the switch marker went out")
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

func TestServerSpliceEndStreamAfterSwitchIsNoop(t *testing.T) {
	_, _, sc := runSpliceFrom(t, bytes.Repeat([]byte("x"), 4096), 512)

	if !sc.down.SwitchedRaw() {
		t.Error("SwitchedRaw() = false after the switch; the connection would go back to the pool mid-stream")
	}
}

type writerConn struct{ w io.Writer }

func (c writerConn) Write(p []byte) (int, error) { return c.w.Write(p) }

// readAsClient is what keepAliveStream.SpliceTo in core/tunnel does, spelled out
// here because that type is unexported in another package: read records until
// the server stops framing, then take the rest of the socket as it comes. It is
// the only place the two sides of the switch are checked against each other.
func readAsClient(t *testing.T, wire net.Conn, dst io.Writer) {
	t.Helper()
	fc := protocol.NewFramedConn(wire, protocol.NewShapeBudget())
	_, err := buf.Copy(buf.NewReader(fc), buf.NewWriter(writerConn{dst}))
	if !errors.Is(err, protocol.ErrSwitchRaw) {
		if err != nil {
			t.Errorf("framed copy: %v", err)
		}
		return
	}
	if _, err := io.Copy(dst, wire); err != nil && err != io.EOF {
		t.Errorf("raw copy: %v", err)
	}
}

func roundTripOverTCP(t *testing.T, payload []byte) []byte {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	cl, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	sv := <-accepted

	srcA, srcB := net.Pipe()
	go func() {
		_, _ = srcB.Write(payload)
		_ = srcB.Close()
	}()
	go func() {
		sc := &serverSpliceConn{Conn: sv, up: protocol.NewFramedConn(sv, protocol.NewShapeBudget()), down: protocol.NewFramedConn(sv, protocol.NewShapeBudget()), raw: sv, left: spliceAfterBytes}
		_, _ = sc.spliceFrom(srcA)
		_ = sc.down.EndStream()
		_ = sv.Close()
	}()

	var got bytes.Buffer
	readAsClient(t, cl, &got)
	return got.Bytes()
}

func TestSpliceRoundTripShortStream(t *testing.T) {
	payload := make([]byte, 40<<10)
	rand.Read(payload)
	if got := roundTripOverTCP(t, payload); !bytes.Equal(got, payload) {
		t.Fatalf("short stream mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

func TestSpliceRoundTripBulkCrossesThreshold(t *testing.T) {
	payload := make([]byte, 4<<20)
	rand.Read(payload)
	if got := roundTripOverTCP(t, payload); !bytes.Equal(got, payload) {
		t.Fatalf("bulk mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}
