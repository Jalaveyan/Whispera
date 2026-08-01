package protocol

import (
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestSeedFingerprintsValidAndCamoReady(t *testing.T) {
	entries, err := seedFingerprintFS.ReadDir("seed_fingerprints")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no embedded seed fingerprints")
	}
	camoKey := make([]byte, 32)
	for i := range camoKey {
		camoKey[i] = byte(i)
	}
	for _, e := range entries {
		raw, err := seedFingerprintFS.ReadFile("seed_fingerprints/" + e.Name())
		if err != nil {
			t.Fatalf("%s: read: %v", e.Name(), err)
		}
		fp := &utls.Fingerprinter{AllowBluntMimicry: true}
		spec, err := fp.FingerprintClientHello(raw)
		if err != nil {
			t.Fatalf("%s: fingerprint: %v", e.Name(), err)
		}
		c0, c1 := net.Pipe()
		u := utls.UClient(c0, &utls.Config{ServerName: "example.com", InsecureSkipVerify: true}, utls.HelloCustom)
		if err := u.ApplyPreset(spec); err != nil {
			t.Fatalf("%s: apply preset: %v", e.Name(), err)
		}
		if err := u.BuildHandshakeState(); err != nil {
			t.Fatalf("%s: build handshake: %v", e.Name(), err)
		}
		hello := u.HandshakeState.Hello
		if hello == nil || len(hello.Random) != 32 {
			t.Fatalf("%s: no hello random", e.Name())
		}
		if ks := extractX25519KeyShare(hello.KeyShares); len(ks) == 0 {
			t.Fatalf("%s: no X25519 keyshare — camo marker cannot apply, would break handshake", e.Name())
		}
		c0.Close()
		c1.Close()
		fp2 := &utls.Fingerprinter{AllowBluntMimicry: true}
		s2, _ := fp2.FingerprintClientHello(raw)
		if !specHandshakeReady(s2) {
			t.Fatalf("%s: not handshake-ready under client config — would be rejected at load", e.Name())
		}
	}
}

func TestSeedFingerprintsLoadIntoPool(t *testing.T) {
	harvestMu.Lock()
	harvestSpecs = nil
	harvestRaw = nil
	harvestKinds = nil
	harvestSeen = map[string]bool{}
	harvestMu.Unlock()

	n := loadSeedFingerprints()
	if n == 0 {
		t.Fatal("loadSeedFingerprints added 0")
	}
	if got := HarvestedFingerprintCount(); got == 0 {
		t.Fatalf("pool empty after seeding, count=%d", got)
	}
}
