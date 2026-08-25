package relay

import (
	"net"
	"testing"
	"time"
)

type headerConn struct {
	net.Conn
	in  []byte
	pos int
}

func (c *headerConn) Read(b []byte) (int, error) {
	if c.pos >= len(c.in) {
		return 0, net.ErrClosed
	}
	n := copy(b, c.in[c.pos:])
	c.pos += n
	return n, nil
}

func (c *headerConn) SetReadDeadline(time.Time) error { return nil }

// FuzzReadProxyStreamHeader feeds arbitrary bytes to the stream header parser.
// This runs on an authenticated connection, but a client that misbehaves — or a
// half-written header — must not take the server down with it.
func FuzzReadProxyStreamHeader(f *testing.F) {
	f.Add([]byte{0x06, 0x00, 0x03, 'a', 'b', 'c', 0x01, 0xbb})
	f.Add([]byte{0x86, 0xff, 0xff})
	f.Add([]byte{0x11, 0x00, 0x00})
	f.Add([]byte{0x06, 0x01, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		h, ok := readProxyStreamHeader(&headerConn{in: data}, 0)
		if !ok {
			return
		}
		if len(h.addr) > 255 {
			t.Fatalf("address of %d bytes accepted", len(h.addr))
		}
		_ = h.target()
		_ = h.network()
	})
}
