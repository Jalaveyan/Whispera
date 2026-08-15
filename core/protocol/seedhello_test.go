package protocol

import (
	"testing"

	"github.com/nekoskin/whispera/core/protocol/camo"
	"github.com/nekoskin/whispera/core/protocol/fingerprint"
	utls "github.com/refraction-networking/utls"
)

func TestSeedHelloBuildsForCamo(t *testing.T) {
	n := fingerprint.PoolSize()
	t.Logf("pool size: %d", n)
	for i := 0; i < n; i++ {
		_, raw, rep := fingerprint.RawAt(i)
		spec, err := fingerprint.SpecFromRaw(raw)
		if err != nil {
			t.Logf("seed %d: SpecFromRaw err: %v", i, err)
			continue
		}
		fingerprint.DropPQKeyShares(spec)
		uc := utls.UClient(nil, &utls.Config{ServerName: "www.google.com"}, utls.HelloCustom)
		if err := uc.ApplyPreset(spec); err != nil {
			t.Logf("seed %d: ApplyPreset err: %v", i, err)
			continue
		}
		if err := uc.BuildHandshakeState(); err != nil {
			t.Logf("seed %d: BuildHandshakeState err: %v", i, err)
			continue
		}
		h := uc.HandshakeState.Hello
		ks := camo.ExtractX25519KeyShare(h.KeyShares)
		t.Logf("seed %d rep=%v: helloRaw=%d bytes, random=%d, keyShares=%d, x25519=%d, helloSNI=%q",
			i, rep.Client, len(h.Raw), len(h.Random), len(h.KeyShares), len(ks), h.ServerName)
		if i == 0 {
			for _, ext := range spec.Extensions {
				if sni, ok := ext.(*utls.SNIExtension); ok {
					t.Logf("  seed0 SNIExtension ServerName=%q", sni.ServerName)
				} else {
					t.Logf("  seed0 ext %T", ext)
				}
			}
		}
	}
}
