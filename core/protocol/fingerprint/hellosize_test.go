package fingerprint

import (
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func helloSize(t *testing.T, id utls.ClientHelloID, drop bool) int {
	t.Helper()
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		t.Fatalf("spec %s: %v", id.Str(), err)
	}
	if drop {
		DropPQKeyShares(&spec)
	}
	c0, c1 := net.Pipe()
	defer c0.Close()
	defer c1.Close()
	u := utls.UClient(c0, &utls.Config{
		ServerName:                         "www.microsoft.com",
		InsecureSkipVerify:                 true,
		PreferSkipResumptionOnNilExtension: true,
	}, utls.HelloCustom)
	if err := u.ApplyPreset(&spec); err != nil {
		t.Fatalf("apply %s: %v", id.Str(), err)
	}
	if err := u.BuildHandshakeState(); err != nil {
		t.Fatalf("build %s: %v", id.Str(), err)
	}
	return len(u.HandshakeState.Hello.Raw)
}

func TestNoHelloLandsInRFC7685Range(t *testing.T) {
	for i := 0; i < PresetCount(); i++ {
		id := PresetAt(i)
		for _, drop := range []bool{false, true} {
			n := helloSize(t, id, drop)
			if n >= 256 && n <= 511 {
				t.Errorf("%s (dropPQ=%v): hello is %d bytes, inside the 256..511 range", id.Str(), drop, n)
			}
		}
	}
}
