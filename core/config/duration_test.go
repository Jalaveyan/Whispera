package config

import (
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestDurationSurvivesRepeatedSaves(t *testing.T) {
	type holder struct {
		D Duration `yaml:"d"`
	}

	h := holder{D: Duration(30 * time.Second)}
	for i := 1; i <= 5; i++ {
		out, err := yaml.Marshal(h)
		if err != nil {
			t.Fatalf("round %d: marshal: %v", i, err)
		}
		var back holder
		if err := yaml.Unmarshal(out, &back); err != nil {
			t.Fatalf("round %d: unmarshal %q: %v", i, out, err)
		}
		if back.D.D() != 30*time.Second {
			t.Fatalf("round %d: %s round-tripped to %v, want 30s", i, out, back.D.D())
		}
		h = back
	}
}

func TestDurationAcceptsPlainSeconds(t *testing.T) {
	var h struct {
		D Duration `yaml:"d"`
	}
	if err := yaml.Unmarshal([]byte("d: 45\n"), &h); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if h.D.D() != 45*time.Second {
		t.Errorf("d = %v, want 45s", h.D.D())
	}
}

func TestFillRepairsCorruptedDurations(t *testing.T) {
	c := *DefaultServerConfig()
	c.Session.KeepaliveInterval = Duration(-1914857 * time.Hour)
	c.Session.SessionTimeout = 0
	c.Server.GracefulStop = Duration(1 << 62)

	if err := c.fill(); err != nil {
		t.Fatalf("fill: %v", err)
	}

	d := DefaultServerConfig()
	if c.Session.KeepaliveInterval != d.Session.KeepaliveInterval {
		t.Errorf("keepalive_interval = %v, want %v", c.Session.KeepaliveInterval.D(), d.Session.KeepaliveInterval.D())
	}
	if c.Session.SessionTimeout != d.Session.SessionTimeout {
		t.Errorf("session_timeout = %v, want %v", c.Session.SessionTimeout.D(), d.Session.SessionTimeout.D())
	}
	if c.Server.GracefulStop != d.Server.GracefulStop {
		t.Errorf("graceful_stop = %v, want %v", c.Server.GracefulStop.D(), d.Server.GracefulStop.D())
	}
}
