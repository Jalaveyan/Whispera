package protocol

import (
	"net"
	"testing"
	"time"
)

type fuzzConn struct {
	net.Conn
	in  []byte
	pos int
}

func (c *fuzzConn) Read(b []byte) (int, error) {
	if c.pos >= len(c.in) {
		return 0, net.ErrClosed
	}
	n := copy(b, c.in[c.pos:])
	c.pos += n
	return n, nil
}

func (c *fuzzConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *fuzzConn) Close() error                     { return nil }
func (c *fuzzConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fuzzConn) SetWriteDeadline(time.Time) error { return nil }
func (c *fuzzConn) SetDeadline(time.Time) error      { return nil }

// FuzzFramedRead throws arbitrary bytes at the record parser. Whatever a peer
// sends — truncated headers, impossible lengths, a switch marker in the middle
// of a stream — the reader must fail, never panic and never hand back memory it
// was not given.
func FuzzFramedRead(f *testing.F) {
	f.Add([]byte{0x17, 0x03, 0x03, 0x00, 0x02, 0x00, 0x00})
	f.Add([]byte{0x17, 0x03, 0x03, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0x16, 0x03, 0x03, 0x00, 0x02, 0x00, 0x05, 0xaa})
	f.Add([]byte{0x17, 0x03, 0x03, 0x00, 0x08, 0x00, 0x06, 1, 2, 3})

	f.Fuzz(func(t *testing.T, data []byte) {
		fc := NewFramedConn(&fuzzConn{in: data}, NewShapeBudget())
		out := make([]byte, 4096)
		for i := 0; i < 64; i++ {
			n, err := fc.Read(out)
			if n < 0 || n > len(out) {
				t.Fatalf("Read returned %d for a %d-byte buffer", n, len(out))
			}
			if err != nil {
				return
			}
		}
	})
}
