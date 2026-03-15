package mtproto

import (
	"encoding/hex"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if len(cfg.DCAddresses) != 5 {
		t.Errorf("expected 5 DCs, got %d", len(cfg.DCAddresses))
	}
	if !cfg.EnableFakeTLS {
		t.Error("expected FakeTLS enabled by default")
	}
}

func TestConfigValidate(t *testing.T) {
	cfg := &Config{}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty secret")
	}

	cfg.Secret = "short"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for short secret")
	}

	cfg.Secret = hex.EncodeToString(make([]byte, 16))
	if err := cfg.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestParseSecretSimple(t *testing.T) {
	secret := hex.EncodeToString(make([]byte, 16))
	parsed, err := ParseSecret(secret)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if parsed.Type != "simple" {
		t.Errorf("expected simple, got %s", parsed.Type)
	}
	if len(parsed.Secret) != 16 {
		t.Errorf("expected 16 byte secret, got %d", len(parsed.Secret))
	}
}

func TestParseSecretSecured(t *testing.T) {
	raw := make([]byte, 17)
	raw[0] = 0xAA
	secret := hex.EncodeToString(raw)
	parsed, err := ParseSecret(secret)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if parsed.Type != "secured" {
		t.Errorf("expected secured, got %s", parsed.Type)
	}
	if parsed.Tag != 0xAA {
		t.Errorf("expected tag 0xAA, got 0x%02X", parsed.Tag)
	}
}

func TestParseSecretFakeTLS(t *testing.T) {
	raw := make([]byte, 17)
	raw[0] = 0xBB
	raw = append(raw, []byte("example.com")...)
	secret := hex.EncodeToString(raw)
	parsed, err := ParseSecret(secret)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if parsed.Type != "faketls" {
		t.Errorf("expected faketls, got %s", parsed.Type)
	}
	if parsed.Domain != "example.com" {
		t.Errorf("expected example.com domain, got %s", parsed.Domain)
	}
}

func TestParseSecretWithPrefix(t *testing.T) {
	inner := hex.EncodeToString(make([]byte, 16))
	secret := "dd" + inner
	parsed, err := ParseSecret(secret)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if parsed.Type != "simple" {
		t.Errorf("expected simple (prefix stripped), got %s", parsed.Type)
	}
}

func TestParseSecretInvalid(t *testing.T) {
	_, err := ParseSecret("not-hex")
	if err == nil {
		t.Error("expected error for invalid hex")
	}

	_, err = ParseSecret(hex.EncodeToString(make([]byte, 5)))
	if err == nil {
		t.Error("expected error for too short secret")
	}
}

func TestMTProtoSessionDecryptHeader(t *testing.T) {
	secret := make([]byte, 16)
	session := NewMTProtoSession(secret)

	header := make([]byte, 64)
	for i := range header {
		header[i] = byte(i)
	}

	err := session.DecryptHeader(header)
	if err != nil {
		t.Fatalf("DecryptHeader error: %v", err)
	}

	if session.clientDecrypt == nil {
		t.Error("expected clientDecrypt to be set")
	}
	if session.clientEncrypt == nil {
		t.Error("expected clientEncrypt to be set")
	}
}

func TestMTProtoSessionEncryptDecrypt(t *testing.T) {
	secret := make([]byte, 16)
	session := NewMTProtoSession(secret)

	header := make([]byte, 64)
	for i := range header {
		header[i] = byte(i * 3)
	}
	_ = session.DecryptHeader(header)

	original := []byte("test data for encryption")
	encrypted := session.EncryptToClient(original)

	if string(encrypted) == string(original) {
		t.Error("encrypted should differ from original")
	}
}

func TestTransportType(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Secret = hex.EncodeToString(make([]byte, 16))
	tr, err := New(cfg)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	if tr.Type() != "mtproto" {
		t.Errorf("expected mtproto, got %s", tr.Type())
	}
}

func TestFactory(t *testing.T) {
	m, err := Factory(nil)
	if err != nil {
		t.Fatalf("factory error: %v", err)
	}
	if m.Name() != ModuleName {
		t.Errorf("expected %s, got %s", ModuleName, m.Name())
	}
}
