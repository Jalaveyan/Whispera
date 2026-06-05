package chameleon

import (
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestHarvestRoundTrip(t *testing.T) {
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

	before := len(harvestSpecs)
	if err := HarvestRawClientHello(rec); err != nil {
		t.Fatalf("HarvestRawClientHello: %v", err)
	}
	if len(harvestSpecs) != before+1 {
		t.Fatalf("harvested spec not added: %d -> %d", before, len(harvestSpecs))
	}
}
