package split_tunnel

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
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

func (stm *SplitTunnelManager) SaveConfig(filename string) error {
	if filename == "" {
		return nil
	}

	stm.config.Rules = stm.rules
	data, err := json.MarshalIndent(stm.config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal split tunnel config: %w", err)
	}

	if err := os.WriteFile(filename, data, 0600); err != nil {
		return fmt.Errorf("failed to write split tunnel config: %w", err)
	}

	return nil
}

func (stm *SplitTunnelManager) AddRule(rule *SplitTunnelRule) {
	rule.Created = time.Now().Unix()
	rule.Modified = time.Now().Unix()
	stm.rules = append(stm.rules, *rule)
}

func (stm *SplitTunnelManager) RemoveRule(index int) bool {
	if index < 0 || index >= len(stm.rules) {
		return false
	}
	stm.rules = append(stm.rules[:index], stm.rules[index+1:]...)
	return true
}

func (stm *SplitTunnelManager) UpdateRule(index int, rule *SplitTunnelRule) bool {
	if index < 0 || index >= len(stm.rules) {
		return false
	}
	rule.Modified = time.Now().Unix()
	stm.rules[index] = *rule
	return true
}

func (stm *SplitTunnelManager) GetRules() []SplitTunnelRule {
	return stm.rules
}

func (stm *SplitTunnelManager) SetMode(mode string) {
	stm.config.Mode = mode
}

func (stm *SplitTunnelManager) SetEnabled(enabled bool) {
	stm.config.Enabled = enabled
}

func (stm *SplitTunnelManager) ShouldTunnel(destIP, destPort, appName string) bool {
	if !stm.config.Enabled {
		return true
	}

	for _, rule := range stm.rules {
		if !rule.Enabled {
			continue
		}

		if stm.matchesRule(&rule, destIP, destPort, appName) {
			return rule.Action == "tunnel"
		}
	}

	return stm.config.DefaultAction == "tunnel"
}

func (stm *SplitTunnelManager) matchesRule(rule *SplitTunnelRule, destIP, destPort, appName string) bool {
	switch rule.Type {
	case "ip":
		return stm.matchesIP(rule.Value, destIP)
	case "domain":
		// domain rules must be matched by hostname, not IP — use ShouldBypassByHostname.
		return false
	case "app":
		return stm.matchesApp(rule.Value, appName)
	case "port":
		return destPort == rule.Value
	default:
		return false
	}
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
	for _, rule := range stm.rules {
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
	for _, rule := range stm.rules {
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

func (stm *SplitTunnelManager) matchesApp(ruleValue, appName string) bool {
	if strings.EqualFold(appName, ruleValue) {
		return true
	}

	if strings.Contains(strings.ToLower(appName), strings.ToLower(ruleValue)) {
		return true
	}

	if stm.appDetector != nil {
		return stm.appDetector.IsProcessRunning(ruleValue)
	}

	return false
}

func (stm *SplitTunnelManager) GetConfig() *SplitTunnelConfig {
	stm.config.Rules = stm.rules
	return stm.config
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

func (stm *SplitTunnelManager) StartAppDetection(interval time.Duration) {
	if stm.appDetector != nil {
		stm.appDetector.StartScanning(interval)
	}
}

func (stm *SplitTunnelManager) StopAppDetection() {
	if stm.appDetector != nil {
		stm.appDetector.StopScanning()
	}
}

func (stm *SplitTunnelManager) GetRunningApps() []string {
	if stm.appDetector == nil {
		return []string{}
	}
	return stm.appDetector.GetExecutableList()
}

func (stm *SplitTunnelManager) GetPopularApps() []string {
	if stm.appDetector == nil {
		return []string{}
	}
	return stm.appDetector.GetPopularApplications()
}

func (stm *SplitTunnelManager) GetSystemApps() []string {
	if stm.appDetector == nil {
		return []string{}
	}
	return stm.appDetector.GetSystemApplications()
}

func (stm *SplitTunnelManager) AddAppRule(appName, action, description string) {
	rule := SplitTunnelRule{
		Type:        "app",
		Value:       appName,
		Action:      action,
		Description: description,
		Enabled:     true,
		Priority:    50,
	}
	stm.AddRule(&rule)
}

func (stm *SplitTunnelManager) GetAppSuggestions() []string {
	if stm.appDetector == nil {
		return []string{}
	}
	return stm.appDetector.SuggestAppRules()
}

func (stm *SplitTunnelManager) ValidateAppRule(ruleValue string) error {
	if stm.appDetector == nil {
		return fmt.Errorf("app detector not initialized")
	}
	return stm.appDetector.ValidateAppRule(ruleValue)
}
