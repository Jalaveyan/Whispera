package protocol

import "testing"

func TestSetForcedFingerprintOverridesPick(t *testing.T) {
	defer SetForcedFingerprint("")

	SetForcedFingerprint("firefox_120")
	id, spec, uaID := pickFingerprint()
	if id.Client != "Firefox" || id.Version != "120" {
		t.Fatalf("got id=%+v, want Firefox 120", id)
	}
	if spec != nil {
		t.Fatalf("forced fingerprint should not carry a harvested spec, got %+v", spec)
	}
	if uaID != id {
		t.Fatalf("uaID should match forced id, got %+v want %+v", uaID, id)
	}
}

func TestSetForcedFingerprintUnknownNameClearsOverride(t *testing.T) {
	defer SetForcedFingerprint("")

	SetForcedFingerprint("chrome")
	if forcedFingerprintID.Client == "" {
		t.Fatalf("expected known name to set an override")
	}

	SetForcedFingerprint("not-a-real-fingerprint")
	if forcedFingerprintID.Client != "" {
		t.Fatalf("unknown name should clear the override, got %+v", forcedFingerprintID)
	}
}

func TestSetForcedFingerprintEmptyRestoresRandomPick(t *testing.T) {
	SetForcedFingerprint("safari")
	SetForcedFingerprint("")
	if forcedFingerprintID.Client != "" {
		t.Fatalf("empty name should clear the override, got %+v", forcedFingerprintID)
	}
}
