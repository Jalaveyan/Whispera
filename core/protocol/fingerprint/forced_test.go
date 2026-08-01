package fingerprint

import (
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestRawFingerprintStoreAndForce(t *testing.T) {
	raw := captureClientHello(t, utls.HelloChrome_133)
	dir := t.TempDir()

	if err := PersistRawFingerprint(dir, raw); err != nil {
		t.Fatalf("persist: %v", err)
	}
	got, ok := FreshestRaw(dir, "chrome")
	if !ok || len(got) == 0 {
		t.Fatalf("freshest chrome not found (classify=%v)", ClassifyClientHello(raw))
	}

	replayable := captureClientHello(t, utls.HelloChrome_120)
	SetForcedRaw(replayable)
	id, spec, _ := pick()
	if id != utls.HelloCustom || spec == nil {
		t.Fatalf("pick did not return the raw spec: id=%v spec=%v", id, spec)
	}
	SetForcedRaw(nil)

	SetForcedRaw(raw)
	defer SetForcedRaw(nil)
	forcedRawMu.RLock()
	fb := forcedRawBytes
	forcedRawMu.RUnlock()
	if fb != nil {
		t.Fatalf("hybrid PQ capture should be rejected as forced-raw")
	}
}
