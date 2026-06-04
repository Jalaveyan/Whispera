package split_tunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"whispera/internal/app_detection"
)

type SplitTunnelRule struct {
	Type        string `json:"type"`
	Value       string `json:"value"`
	Action      string `json:"action"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
	Priority    int    `json:"priority"`
	Created     int64  `json:"created"`
	Modified    int64  `json:"modified"`
}

type SplitTunnelConfig struct {
	Mode          string            `json:"mode"`
	Rules         []SplitTunnelRule `json:"rules"`
	DefaultAction string            `json:"default_action"`
	Enabled       bool              `json:"enabled"`
	Version       string            `json:"version"`
}

type SplitTunnelManager struct {
	mu          sync.RWMutex
	config      *SplitTunnelConfig
	rules       []SplitTunnelRule
	appDetector *app_detection.AppDetector
}

func NewSplitTunnelManager() *SplitTunnelManager {
	return &SplitTunnelManager{
		config: &SplitTunnelConfig{
			Mode:          "exclude",
			DefaultAction: "tunnel",
			Enabled:       false,
			Version:       "1.0",
			Rules:         []SplitTunnelRule{},
		},
		rules:       []SplitTunnelRule{},
		appDetector: app_detection.NewAppDetector(),
	}
}

func (stm *SplitTunnelManager) LoadConfig(filename string) error {
	if filename == "" {
		return nil
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read split tunnel config: %w", err)
	}

	var config SplitTunnelConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse split tunnel config: %w", err)
	}

	stm.config = &config
	stm.rules = config.Rules

	return nil
}

func (stm *SplitTunnelManager) AddRule(rule *SplitTunnelRule) {
	rule.Created = time.Now().Unix()
	rule.Modified = time.Now().Unix()
	stm.mu.Lock()
	stm.rules = append(stm.rules, *rule)
	stm.mu.Unlock()
}

func (stm *SplitTunnelManager) SetMode(mode string) {
	stm.config.Mode = mode
}

func (stm *SplitTunnelManager) SetEnabled(enabled bool) {
	stm.config.Enabled = enabled
}

// ShouldBypass returns true when addr (hostname or IP) should be routed directly.
// For IP addresses it checks CIDR rules; for hostnames it checks domain rules.
// Use this as the single entry point in BypassFunc.
func (stm *SplitTunnelManager) ShouldBypass(addr string, port uint16) bool {
	if !stm.config.Enabled {
		return false
	}
	if net.ParseIP(addr) != nil {
		return stm.ShouldBypassByIP(addr)
	}
	return stm.ShouldBypassByHostname(addr)
}

// ShouldBypassByIP returns true when the IP matches a CIDR/exact-IP rule with action "direct".
func (stm *SplitTunnelManager) ShouldBypassByIP(ipStr string) bool {
	if !stm.config.Enabled {
		return false
	}
	stm.mu.RLock()
	rules := stm.rules
	stm.mu.RUnlock()
	for _, rule := range rules {
		if !rule.Enabled || rule.Type != "ip" {
			continue
		}
		if stm.matchesIP(rule.Value, ipStr) {
			return rule.Action == "direct"
		}
	}
	return false
}

// ShouldBypassByHostname returns true when the hostname matches a domain rule
// with action "direct". Call this BEFORE DNS resolution, while the hostname
// is still available.
func (stm *SplitTunnelManager) ShouldBypassByHostname(hostname string) bool {
	if !stm.config.Enabled {
		return false
	}
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	stm.mu.RLock()
	rules := stm.rules
	stm.mu.RUnlock()
	for _, rule := range rules {
		if !rule.Enabled || rule.Type != "domain" {
			continue
		}
		if matchesDomainSuffix(hostname, strings.ToLower(rule.Value)) {
			return rule.Action == "direct"
		}
	}
	return false
}

// matchesDomainSuffix reports whether host equals pattern or is a subdomain of it.
// pattern may start with "*." for explicit wildcard (optional — plain suffix works too).
func matchesDomainSuffix(host, pattern string) bool {
	pattern = strings.TrimPrefix(pattern, "*.")
	if host == pattern {
		return true
	}
	return strings.HasSuffix(host, "."+pattern)
}

func (stm *SplitTunnelManager) matchesIP(ruleValue, destIP string) bool {
	if ruleValue == destIP {
		return true
	}

	_, network, err := net.ParseCIDR(ruleValue)
	if err != nil {
		return false
	}

	ip := net.ParseIP(destIP)
	if ip == nil {
		return false
	}

	return network.Contains(ip)
}

// PreResolveAndCacheIPs resolves all bypass-listed domains using the provided
// resolver and adds their IPs as /32 direct rules. Call this at startup before
// VPN connects so that apps which pre-resolve a hostname (and send the bare IP
// to SOCKS5) are still routed directly — hostname bypass alone would miss them.
func (stm *SplitTunnelManager) PreResolveAndCacheIPs(ctx context.Context, resolver *net.Resolver) int {
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	var newRules []SplitTunnelRule
	now := time.Now().Unix()

	for _, domain := range russianBypassDomains {
		addrs, err := resolver.LookupIPAddr(ctx, domain)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			newRules = append(newRules, SplitTunnelRule{
				Type:        "ip",
				Value:       a.IP.String() + "/32",
				Action:      "direct",
				Description: "auto:" + domain,
				Enabled:     true,
				Priority:    89,
				Created:     now,
				Modified:    now,
			})
		}
	}

	if len(newRules) == 0 {
		return 0
	}

	stm.mu.Lock()
	stm.rules = append(stm.rules, newRules...)
	stm.mu.Unlock()

	return len(newRules)
}

// russianBypassDomains is the built-in list of Russian services that should
// resolve via system DNS and route directly (not through the VPN) to ensure
// they work correctly. These are either whitelisted by RKN or require a
// Russian IP for proper operation (banking, government portals, etc.).
var russianBypassDomains = []string{
	// Yandex ecosystem
	"yandex.ru", "ya.ru", "yandex.net",
	"disk.yandex.ru", "webdav.yandex.ru",
	"mail.yandex.ru", "passport.yandex.ru",
	"maps.yandex.ru", "api-maps.yandex.net",
	"mc.yandex.ru", "metrika.yandex.ru",
	// VK / Mail.ru
	"vk.com", "vkuseraudio.net", "vkuservideo.net",
	"userapi.com", "vk.me",
	"mail.ru", "ok.ru", "mycdn.me",
	// Banking & finance (require Russian IP for 3DS, mobile bank)
	"sberbank.ru", "online.sberbank.ru", "sberonline.ru",
	"tinkoff.ru", "acdn.tinkoff.ru",
	"alfabank.ru", "vtb.ru", "raiffeisen.ru",
	"cbr.ru",
	// Government
	"gosuslugi.ru", "esia.gosuslugi.ru",
	"nalog.ru", "lkfl.nalog.ru",
	"mos.ru", "pgu.mos.ru",
	"pfr.gov.ru", "fss.ru",
	// Marketplaces & delivery
	"wildberries.ru", "ozon.ru", "avito.ru",
	"cdek.ru", "pochta.ru",
	// Media & search
	"rutube.ru", "dzen.ru",
	"rbc.ru", "ria.ru", "tass.ru",
	"hh.ru", "superjob.ru",
}

// AddRussianWhitelist adds built-in direct-routing rules for common Russian
// services. Call after NewSplitTunnelManager() to enable YaDisk/whitelist bypass.
func (stm *SplitTunnelManager) AddRussianWhitelist() {
	for _, domain := range russianBypassDomains {
		stm.AddRule(&SplitTunnelRule{
			Type:        "domain",
			Value:       domain,
			Action:      "direct",
			Description: "Russian service — use direct route",
			Enabled:     true,
			Priority:    90,
		})
	}
}

func (stm *SplitTunnelManager) CreateDefaultRules() {
	rule := SplitTunnelRule{
		Type:        "ip",
		Value:       "192.168.0.0/16",
		Action:      "direct",
		Description: "Local network (192.168.x.x)",
		Enabled:     true,
		Priority:    100,
	}
	stm.AddRule(&rule)

	rule = SplitTunnelRule{
		Type:        "ip",
		Value:       "10.0.0.0/8",
		Action:      "direct",
		Description: "Local network (10.x.x.x)",
		Enabled:     true,
		Priority:    100,
	}
	stm.AddRule(&rule)

	rule = SplitTunnelRule{
		Type:        "ip",
		Value:       "172.16.0.0/12",
		Action:      "direct",
		Description: "Local network (172.16-31.x.x)",
		Enabled:     true,
		Priority:    100,
	}
	stm.AddRule(&rule)

	rule = SplitTunnelRule{
		Type:        "ip",
		Value:       "127.0.0.0/8",
		Action:      "direct",
		Description: "Localhost",
		Enabled:     true,
		Priority:    100,
	}
	stm.AddRule(&rule)
}
