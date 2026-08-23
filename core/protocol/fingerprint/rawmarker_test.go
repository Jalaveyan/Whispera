package fingerprint

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/nekoskin/whispera/core/protocol/camo"

	utls "github.com/refraction-networking/utls"
)

func TestRawFingerprintCarriesX25519KeyShare(t *testing.T) {
	b64 := strings.TrimSpace(os.Getenv("WHISPERA_TEST_FPRAW"))
	if b64 == "" {
		t.Skip("WHISPERA_TEST_FPRAW не задан")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}

	spec, err := SpecFromRaw(raw)
	if err != nil {
		t.Fatalf("SpecFromRaw: %v", err)
	}
	if DropPQEnabled() {
		DropPQKeyShares(spec)
	}

	u := utls.UClient(nil, &utls.Config{ServerName: "www.google.com"}, utls.HelloCustom)
	if err := u.ApplyPreset(spec); err != nil {
		t.Fatalf("ApplyPreset: %v", err)
	}
	if err := u.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState: %v", err)
	}

	hello := u.HandshakeState.Hello
	if hello == nil || len(hello.Random) != 32 {
		t.Fatal("нет пригодного hello")
	}
	share := camo.ExtractX25519KeyShare(hello.KeyShares)
	groups := make([]uint16, 0, len(hello.KeyShares))
	for _, ks := range hello.KeyShares {
		groups = append(groups, uint16(ks.Group))
	}
	t.Logf("key share groups: %v, X25519 share = %d байт", groups, len(share))
	if len(share) == 0 {
		t.Error("сырой отпечаток не даёт X25519 key share — маркер не построится, сервер уведёт дозвон в decoy")
	}
}
