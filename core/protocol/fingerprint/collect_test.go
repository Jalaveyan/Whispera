package fingerprint

import (
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestCollectRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	uc := utls.UClient(c1, &utls.Config{ServerName: "example.com"}, utls.HelloChrome_133)
	if err := uc.BuildHandshakeState(); err != nil {
		t.Skipf("BuildHandshakeState: %v", err)
	}
	if uc.HandshakeState.Hello == nil || len(uc.HandshakeState.Hello.Raw) == 0 {
		t.Skip("no marshaled ClientHello available")
	}
	raw := uc.HandshakeState.Hello.Raw

	rec := make([]byte, 5+len(raw))
	rec[0], rec[1], rec[2] = 0x16, 0x03, 0x01
	rec[3], rec[4] = byte(len(raw)>>8), byte(len(raw))
	copy(rec[5:], raw)

	before := len(collectSpecs)
	if err := CollectRawClientHello(rec); err != nil {
		t.Fatalf("CollectRawClientHello: %v", err)
	}
	if len(collectSpecs) != before+1 {
		t.Fatalf("collected spec not added: %d -> %d", before, len(collectSpecs))
	}
}
