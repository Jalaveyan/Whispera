package split_tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRules(t *testing.T, cfg SplitTunnelConfig) string {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigKeepsExistingRules(t *testing.T) {
	stm := NewSplitTunnelManager()
	stm.CreateDefaultRules()
	stm.SetEnabled(true)

	path := writeRules(t, SplitTunnelConfig{
		Rules: []SplitTunnelRule{{
			Type: "domain", Value: "example.com", Action: "direct", Enabled: true, Priority: 50,
		}},
	})
	if err := stm.LoadConfig(path); err != nil {
		t.Fatal(err)
	}

	if !stm.ShouldBypassByHostname("example.com") {
		t.Fatal("user rule must apply after LoadConfig")
	}
	if !stm.ShouldBypassByIP("192.168.1.5") {
		t.Fatal("LoadConfig must not wipe rules added earlier — user routes used to erase the bypass list")
	}
}

func TestLoadConfigKeepsEnabled(t *testing.T) {
	stm := NewSplitTunnelManager()
	stm.SetEnabled(true)

	path := writeRules(t, SplitTunnelConfig{
		Rules: []SplitTunnelRule{{
			Type: "domain", Value: "example.com", Action: "direct", Enabled: true,
		}},
	})
	if err := stm.LoadConfig(path); err != nil {
		t.Fatal(err)
	}

	if !stm.isEnabled() {
		t.Fatal("a rules file without \"enabled\" used to switch split tunneling off entirely")
	}
}

func TestUserRuleOverridesLowerPriority(t *testing.T) {
	stm := NewSplitTunnelManager()
	stm.SetEnabled(true)

	stm.AddRule(&SplitTunnelRule{
		Type: "domain", Value: "vk.com", Action: "direct", Enabled: true, Priority: 10,
	})
	stm.AddRule(&SplitTunnelRule{
		Type: "domain", Value: "vk.com", Action: "tunnel", Enabled: true, Priority: 90,
	})

	if stm.ShouldBypassByHostname("vk.com") {
		t.Fatal("higher priority rule must win regardless of insertion order")
	}
}

func TestLocalNetworksBypass(t *testing.T) {
	stm := NewSplitTunnelManager()
	stm.CreateDefaultRules()
	stm.SetEnabled(true)

	for _, ip := range []string{"192.168.1.5", "10.1.2.3", "127.0.0.1"} {
		if !stm.ShouldBypassByIP(ip) {
			t.Fatalf("local address %s must bypass the tunnel", ip)
		}
	}
	if stm.ShouldBypassByIP("8.8.8.8") {
		t.Fatal("public address must not bypass by default")
	}
}

func geoWith(t *testing.T, cidrs ...string) *GeoIPSet {
	t.Helper()
	g := NewGeoIPSet()
	ranges, err := parseGeoIP(strings.NewReader(strings.Join(cidrs, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	g.ranges = ranges
	return g
}

func TestBypassByCountryUsesResolvedAddress(t *testing.T) {
	stm := NewSplitTunnelManager()
	stm.SetEnabled(true)
	stm.SetGeoIP(geoWith(t, "176.114.122.0/24"))

	calls := 0
	stm.SetResolver(func(ctx context.Context, host string) ([]net.IP, error) {
		calls++
		switch host {
		case "avito.ru":
			return []net.IP{net.ParseIP("176.114.122.24")}, nil
		default:
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		}
	})

	if !stm.ShouldBypassByHostname("avito.ru") {
		t.Fatal("host resolving inside the country list must go direct")
	}
	if stm.ShouldBypassByHostname("example.com") {
		t.Fatal("host outside the list must stay in the tunnel")
	}

	stm.ShouldBypassByHostname("avito.ru")
	if calls != 2 {
		t.Fatalf("verdict must be cached, got %d lookups for 3 requests", calls)
	}
}

func TestBypassByCountryTunnelsOnResolveFailure(t *testing.T) {
	stm := NewSplitTunnelManager()
	stm.SetEnabled(true)
	stm.SetGeoIP(geoWith(t, "176.114.122.0/24"))
	stm.SetResolver(func(ctx context.Context, host string) ([]net.IP, error) {
		return nil, errors.New("no answer")
	})

	if stm.ShouldBypassByHostname("avito.ru") {
		t.Fatal("an unresolvable host must stay in the tunnel, not leak out in the clear")
	}
}

func TestBypassByCountryWithoutResolver(t *testing.T) {
	stm := NewSplitTunnelManager()
	stm.SetEnabled(true)
	stm.SetGeoIP(geoWith(t, "176.114.122.0/24"))

	if stm.ShouldBypassByHostname("avito.ru") {
		t.Fatal("before the tunnel is up there is nothing to resolve through — everything must tunnel")
	}
}

func TestBypassByCountryCoversIPv6(t *testing.T) {
	stm := NewSplitTunnelManager()
	stm.SetEnabled(true)
	stm.SetGeoIP(geoWith(t, "2a02:6b8::/32", "176.114.122.0/24"))
	stm.SetResolver(func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("2a02:6b8:23::225")}, nil
	})

	if !stm.ShouldBypassByHostname("yandex.ru") {
		t.Fatal("a host reachable only over IPv6 must still match the country list")
	}
	if !stm.ShouldBypassByIP("2a02:6b8:23::225") {
		t.Fatal("IPv6 literal must match the country list")
	}
	if stm.ShouldBypassByIP("2606:4700::1111") {
		t.Fatal("foreign IPv6 must stay in the tunnel")
	}
	if !stm.ShouldBypassByIP("176.114.122.24") {
		t.Fatal("IPv4 must keep working alongside IPv6")
	}
}

func TestVerdictCacheStaysBounded(t *testing.T) {
	stm := NewSplitTunnelManager()
	stm.SetEnabled(true)
	stm.SetGeoIP(geoWith(t, "176.114.122.0/24"))
	stm.SetResolver(func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("8.8.8.8")}, nil
	})

	for i := 0; i < verdictMax*2; i++ {
		stm.ShouldBypassByHostname(fmt.Sprintf("host%d.example.com", i))
	}

	stm.mu.RLock()
	n := len(stm.verdicts)
	stm.mu.RUnlock()
	if n > verdictMax {
		t.Fatalf("verdict cache grew to %d entries, it must not accumulate without bound", n)
	}
}

func TestAppRuleForcesTunnelOverGeoIP(t *testing.T) {
	stm := NewSplitTunnelManager()
	stm.SetEnabled(true)
	stm.CreateDefaultRules()
	stm.SetGeoIP(geoWith(t, "176.114.122.0/24"))
	stm.SetResolver(func(ctx context.Context, host string) ([]net.IP, error) {
		if host == "avito.ru" {
			return []net.IP{net.ParseIP("176.114.122.24")}, nil
		}
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	})

	if !stm.ShouldBypassByHostname("avito.ru") {
		t.Fatal("without a rule the country list decides")
	}

	if err := stm.LoadAppRules(`[
		{"kind":"domain-suffix","suffix":"avito.ru","action":"PROXY"},
		{"kind":"domain-keyword","keyword":"tracker","action":"PROXY"},
		{"kind":"domain-exact","domain":"vk.com","action":"DIRECT"},
		{"kind":"ip-cidr","cidr":"5.255.255.0/24","action":"DIRECT"},
		{"kind":"domain-suffix","suffix":"ads.example","action":"REJECT"}
	]`); err != nil {
		t.Fatal(err)
	}

	if stm.ShouldBypassByHostname("avito.ru") {
		t.Fatal("an explicit tunnel rule must beat the country list")
	}
	if stm.ShouldBypassByHostname("my.tracker.ru") {
		t.Fatal("keyword rule must apply")
	}
	if !stm.ShouldBypassByHostname("vk.com") {
		t.Fatal("exact rule must apply")
	}
	if stm.ShouldBypassByHostname("sub.vk.com") {
		t.Fatal("exact rule must not match subdomains")
	}
	if !stm.ShouldBypassByIP("5.255.255.10") {
		t.Fatal("ip-cidr rule must apply")
	}
}

func geoStm(t *testing.T) *SplitTunnelManager {
	t.Helper()
	stm := NewSplitTunnelManager()
	stm.SetEnabled(true)
	stm.SetGeoIP(geoWith(t, "176.114.122.0/24"))
	stm.SetResolver(func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("176.114.122.24")}, nil
	})
	return stm
}

func TestCountryBypassFollowsTheToggle(t *testing.T) {
	on := geoStm(t)
	if err := on.LoadAppRules(`[{"kind":"geoip","action":"DIRECT"}]`); err != nil {
		t.Fatal(err)
	}
	if !on.ShouldBypassByHostname("avito.ru") || !on.ShouldBypassByIP("176.114.122.24") {
		t.Fatal("with the toggle on, the country list must send Russian addresses direct")
	}

	off := geoStm(t)
	if err := off.LoadAppRules(`[]`); err != nil {
		t.Fatal(err)
	}
	if off.ShouldBypassByHostname("avito.ru") {
		t.Fatal("with the toggle off the country list must stop applying — it could not be switched off before")
	}
	if off.ShouldBypassByIP("176.114.122.24") {
		t.Fatal("the toggle must switch off the country list for literal addresses too")
	}

	off.CreateDefaultRules()
	if !off.ShouldBypassByIP("192.168.1.5") {
		t.Fatal("switching the country list off must not disturb local networks")
	}
}

func TestCountryBypassOnByDefault(t *testing.T) {
	stm := geoStm(t)
	if !stm.ShouldBypassByHostname("avito.ru") {
		t.Fatal("without any app rules (desktop, CLI) the country list stays on")
	}
}
