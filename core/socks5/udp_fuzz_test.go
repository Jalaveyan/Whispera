package socks5

import "testing"

// FuzzParseUDPHeader feeds arbitrary datagrams to the SOCKS5 UDP header parser.
// The packet comes from whoever can reach the local port, so a malformed one
// must be rejected, not panic the relay.
func FuzzParseUDPHeader(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 127, 0, 0, 1, 0, 53})
	f.Add([]byte{0, 0, 0, 3, 5, 'a', 'b', 'c', 'd', 'e', 0, 53})
	f.Add([]byte{0, 0, 0, 4})
	f.Add([]byte{0, 0, 0, 3, 255})

	f.Fuzz(func(t *testing.T, data []byte) {
		host, port, payload, err := parseUDPHeader(data)
		if err != nil {
			return
		}
		if len(payload) > len(data) {
			t.Fatalf("payload %d bytes out of a %d-byte packet", len(payload), len(data))
		}
		_, _ = host, port
	})
}
