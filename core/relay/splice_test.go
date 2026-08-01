package relay

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

func decodeSpliceStream(t *testing.T, r io.Reader, padRecords int) []byte {
	t.Helper()
	var out []byte
	for i := 0; i < padRecords; i++ {
		var hdr [5]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if err == io.EOF {
				return out
			}
			t.Fatalf("read record header: %v", err)
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
		out = append(out, rec[2:2+dataLen]...)
	}
	rest, _ := io.ReadAll(r)
	return append(out, rest...)
}

func TestServerSpliceFromRoundTrip(t *testing.T) {
	rawA, rawB := net.Pipe()
	srcA, srcB := net.Pipe()
	sc := &serverSpliceConn{Conn: rawA, raw: rawA, padLeft: spliceRecordsToPad}

	payload := bytes.Repeat([]byte("0123456789abcdef"), 5000)

	go func() {
		_, _ = srcB.Write(payload)
		_ = srcB.Close()
	}()
	go func() {
		_, _ = sc.spliceFrom(srcA)
		_ = rawA.Close()
	}()

	got := decodeSpliceStream(t, rawB, spliceRecordsToPad)
	if !bytes.Equal(got, payload) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}
