package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodConfig = `server:
  name: whispera
  listen_addr: "0.0.0.0:443"
  private_key: "secret-key-value"
whispera:
  enabled: true
  listen_addr: ":443"
`

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadRejectsBrokenConfigInsteadOfFallingBackToDefaults(t *testing.T) {
	broken := goodConfig + `
whispera:
  enabled: false
`
	path := writeConfig(t, broken)

	p := &Provider{config: DefaultServerConfig()}
	err := p.Load(path)
	if err == nil {
		t.Fatal("duplicate key must fail the load: starting on defaults disables the tunnel and wipes private_key on the next save")
	}
	if !strings.Contains(err.Error(), "refusing to start") {
		t.Fatalf("error must explain the refusal, got: %v", err)
	}
}

func TestLoadKeepsPreviousConfigWhenParsingFails(t *testing.T) {
	path := writeConfig(t, goodConfig)

	p := &Provider{config: DefaultServerConfig()}
	if err := p.Load(path); err != nil {
		t.Fatalf("valid config must load: %v", err)
	}
	loaded := p.GetConfig().Server.PrivateKey
	if loaded != "secret-key-value" {
		t.Fatalf("private key = %q, want it loaded from file", loaded)
	}

	if err := os.WriteFile(path, []byte(goodConfig+"\nserver:\n  name: dup\n"), 0600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if err := p.Load(path); err == nil {
		t.Fatal("broken reload must fail")
	}
	if got := p.GetConfig().Server.PrivateKey; got != "secret-key-value" {
		t.Fatalf("previous config must survive a failed reload, private key = %q", got)
	}
}

func TestSaveConfigBacksUpPreviousFile(t *testing.T) {
	path := writeConfig(t, goodConfig)

	p := &Provider{config: DefaultServerConfig(), configPath: path}
	if err := p.Load(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := p.SaveConfig(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	backup, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatalf("backup must exist before overwrite: %v", err)
	}
	if !strings.Contains(string(backup), "secret-key-value") {
		t.Fatal("backup must hold the pre-overwrite content")
	}
}
