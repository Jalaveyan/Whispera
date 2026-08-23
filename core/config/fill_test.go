package config

import (
	"strings"
	"testing"
)

func TestFillRestoresZeroedFields(t *testing.T) {
	c := *DefaultServerConfig()
	c.Server.ListenAddr = ""
	c.Server.MTU = 0
	c.Server.Workers = 0
	c.Session.MaxSessions = 0

	if err := c.fill(); err != nil {
		t.Fatalf("fill on a zeroed config: %v", err)
	}

	d := DefaultServerConfig()
	if c.Server.ListenAddr != d.Server.ListenAddr {
		t.Errorf("listen_addr = %q, want %q", c.Server.ListenAddr, d.Server.ListenAddr)
	}
	if c.Server.MTU != d.Server.MTU {
		t.Errorf("mtu = %d, want %d", c.Server.MTU, d.Server.MTU)
	}
	if c.Server.Workers != d.Server.Workers {
		t.Errorf("workers = %d, want %d", c.Server.Workers, d.Server.Workers)
	}
	if c.Session.MaxSessions != d.Session.MaxSessions {
		t.Errorf("max_sessions = %d, want %d", c.Session.MaxSessions, d.Session.MaxSessions)
	}
}

func TestFillRejectsValuesItCannotRepair(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*ServerConfig)
		want string
	}{
		{"tiny mtu", func(c *ServerConfig) { c.Server.MTU = 100 }, "server.mtu"},
		{"huge mtu", func(c *ServerConfig) { c.Server.MTU = 70000 }, "server.mtu"},
		{"negative sessions", func(c *ServerConfig) { c.Session.MaxSessions = -1 }, "session.max_sessions"},
		{"listen without port", func(c *ServerConfig) { c.Server.ListenAddr = "0.0.0.0" }, "server.listen_addr"},
		{"whispera listen without port", func(c *ServerConfig) {
			c.Whispera.Enabled = true
			c.Whispera.ListenAddr = "443"
		}, "whispera.listen_addr"},
	}

	for _, tc := range cases {
		c := *DefaultServerConfig()
		tc.mut(&c)
		err := c.fill()
		if err == nil {
			t.Errorf("%s: accepted", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q does not name %s", tc.name, err, tc.want)
		}
	}
}

func TestFillAcceptsShippedDefaults(t *testing.T) {
	c := *DefaultServerConfig()
	if err := c.fill(); err != nil {
		t.Fatalf("the shipped defaults must be valid: %v", err)
	}
}
