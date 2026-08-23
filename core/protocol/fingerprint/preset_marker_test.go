package fingerprint

import (
	"testing"

	"github.com/nekoskin/whispera/core/protocol/camo"

	utls "github.com/refraction-networking/utls"
)

func TestEveryPresetCarriesX25519KeyShare(t *testing.T) {
	for i := range PresetCount() {
		id := PresetAt(i)

		spec, err := utls.UTLSIdToSpec(id)
		if err != nil {
			t.Fatalf("arm %d (%s): spec: %v", i, id.Client, err)
		}
		if DropPQEnabled() {
			DropPQKeyShares(&spec)
		}

		u := utls.UClient(nil, &utls.Config{ServerName: "www.google.com"}, utls.HelloCustom)
		if err := u.ApplyPreset(&spec); err != nil {
			t.Fatalf("arm %d (%s): apply: %v", i, id.Client, err)
		}
		if err := u.BuildHandshakeState(); err != nil {
			t.Fatalf("arm %d (%s): build: %v", i, id.Client, err)
		}

		hello := u.HandshakeState.Hello
		if hello == nil || len(hello.Random) != 32 {
			t.Fatalf("arm %d (%s): no usable hello", i, id.Client)
		}
		if share := camo.ExtractX25519KeyShare(hello.KeyShares); len(share) == 0 {
			groups := make([]uint16, 0, len(hello.KeyShares))
			for _, ks := range hello.KeyShares {
				groups = append(groups, uint16(ks.Group))
			}
			t.Errorf("arm %d (%s): no X25519 key share — the camo marker cannot be built, "+
				"the server will relay this dial to the decoy; key share groups present: %v",
				i, id.Client, groups)
		}
	}
}
