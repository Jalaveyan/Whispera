package split_tunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
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
	mu        sync.RWMutex
	config    *SplitTunnelConfig
	rules     []SplitTunnelRule
	geo       *GeoIPSet
	resolve   ResolveFunc
	byCountry bool
	verdicts  map[string]verdict
	pending   map[string]bool
}

type ResolveFunc func(ctx context.Context, host string) ([]net.IP, error)

type verdict struct {
	bypass  bool
	expires time.Time
}

const (
	verdictTTL      = 10 * time.Minute
	resolveTimeout  = 3 * time.Second
	resolveWait     = 300 * time.Millisecond
	verdictMax      = 4096
	appRulePriority = 200
)

func NewSplitTunnelManager() *SplitTunnelManager {
	return &SplitTunnelManager{
		config: &SplitTunnelConfig{
			Mode:          "exclude",
			DefaultAction: "tunnel",
			Enabled:       false,
			Version:       "1.0",
			Rules:         []SplitTunnelRule{},
		},
		rules:     []SplitTunnelRule{},
		byCountry: true,
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

	stm.mu.Lock()
	if config.Mode != "" {
		stm.config.Mode = config.Mode
	}
	if config.DefaultAction != "" {
		stm.config.DefaultAction = config.DefaultAction
	}
	stm.rules = append(stm.rules, config.Rules...)
	sortRulesByPriority(stm.rules)
	stm.mu.Unlock()

	return nil
}

func (stm *SplitTunnelManager) AddRule(rule *SplitTunnelRule) {
	rule.Created = time.Now().Unix()
	rule.Modified = time.Now().Unix()
	stm.mu.Lock()
	stm.rules = append(stm.rules, *rule)
	sortRulesByPriority(stm.rules)
	stm.mu.Unlock()
}

func sortRulesByPriority(rules []SplitTunnelRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		return rules[i].Priority > rules[j].Priority
	})
}

func (stm *SplitTunnelManager) SetMode(mode string) {
	stm.mu.Lock()
	stm.config.Mode = mode
	stm.mu.Unlock()
}

func (stm *SplitTunnelManager) SetEnabled(enabled bool) {
	stm.mu.Lock()
	stm.config.Enabled = enabled
	stm.mu.Unlock()
}

func (stm *SplitTunnelManager) isEnabled() bool {
	stm.mu.RLock()
	defer stm.mu.RUnlock()
	return stm.config.Enabled
}

func (stm *SplitTunnelManager) ShouldBypass(addr string, port uint16) bool {
	if !stm.isEnabled() {
		return false
	}
	if net.ParseIP(addr) != nil {
		return stm.ShouldBypassByIP(addr)
	}
	return stm.ShouldBypassByHostname(addr)
}

func (stm *SplitTunnelManager) ShouldBypassByIP(ipStr string) bool {
	if !stm.isEnabled() {
		return false
	}
	stm.mu.RLock()
	rules := stm.rules
	geo, byCountry := stm.geo, stm.byCountry
	stm.mu.RUnlock()
	for _, rule := range rules {
		if !rule.Enabled || rule.Type != "ip" {
			continue
		}
		if stm.matchesIP(rule.Value, ipStr) {
			return rule.Action == "direct"
		}
	}
	if geo != nil && byCountry {
		if ip := net.ParseIP(ipStr); ip != nil {
			return geo.Contains(ip)
		}
	}
	return false
}

func (stm *SplitTunnelManager) SetGeoIP(geo *GeoIPSet) {
	stm.mu.Lock()
	stm.geo = geo
	stm.mu.Unlock()
}

func (stm *SplitTunnelManager) ShouldBypassByHostname(hostname string) bool {
	if !stm.isEnabled() {
		return false
	}
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	stm.mu.RLock()
	rules := stm.rules
	stm.mu.RUnlock()
	for _, rule := range rules {
		if !rule.Enabled || !matchesDomainRule(rule, hostname) {
			continue
		}
		return rule.Action == "direct"
	}
	return stm.bypassByCountry(hostname)
}

func (stm *SplitTunnelManager) bypassByCountry(hostname string) bool {
	stm.mu.RLock()
	geo, resolve, byCountry := stm.geo, stm.resolve, stm.byCountry
	v, ok := stm.verdicts[hostname]
	stm.mu.RUnlock()

	if !byCountry {
		return false
	}
	if ok && time.Now().Before(v.expires) {
		return v.bypass
	}
	if geo == nil || resolve == nil || geo.Len() == 0 {
		return false
	}

	// Getting this wrong sends a domestic bank through a foreign address, so the
	// answer is worth waiting for — but only as long as an answer normally takes.
	// Past that the connection goes through the tunnel, which is correct if
	// slower, and the verdict is finished behind it for next time.
	ctx, cancel := context.WithTimeout(context.Background(), resolveWait)
	defer cancel()
	ips, err := resolve(ctx, hostname)
	if err != nil {
		stm.learnInBackground(hostname, geo, resolve)
		return false
	}
	return stm.recordCountry(hostname, geo, ips)
}

func (stm *SplitTunnelManager) learnInBackground(hostname string, geo *GeoIPSet, resolve ResolveFunc) {
	stm.mu.Lock()
	if stm.pending == nil {
		stm.pending = make(map[string]bool)
	}
	if stm.pending[hostname] {
		stm.mu.Unlock()
		return
	}
	stm.pending[hostname] = true
	stm.mu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
		defer cancel()
		ips, err := resolve(ctx, hostname)
		if err == nil {
			stm.recordCountry(hostname, geo, ips)
		}
		stm.mu.Lock()
		delete(stm.pending, hostname)
		stm.mu.Unlock()
	}()
}

func (stm *SplitTunnelManager) recordCountry(hostname string, geo *GeoIPSet, ips []net.IP) bool {
	bypass := false
	for _, ip := range ips {
		if geo.Contains(ip) {
			bypass = true
			break
		}
	}

	stm.mu.Lock()
	if stm.verdicts == nil || len(stm.verdicts) >= verdictMax {
		stm.pruneVerdicts()
	}
	stm.verdicts[hostname] = verdict{bypass: bypass, expires: time.Now().Add(verdictTTL)}
	stm.mu.Unlock()

	return bypass
}

func (stm *SplitTunnelManager) pruneVerdicts() {
	if stm.verdicts == nil {
		stm.verdicts = make(map[string]verdict)
		return
	}
	now := time.Now()
	for host, v := range stm.verdicts {
		if now.After(v.expires) {
			delete(stm.verdicts, host)
		}
	}
	if len(stm.verdicts) >= verdictMax {
		stm.verdicts = make(map[string]verdict)
	}
}

func (stm *SplitTunnelManager) SetResolver(fn ResolveFunc) {
	stm.mu.Lock()
	stm.resolve = fn
	stm.verdicts = nil
	stm.mu.Unlock()
}

type appRule struct {
	Kind    string `json:"kind"`
	Suffix  string `json:"suffix,omitempty"`
	Keyword string `json:"keyword,omitempty"`
	Domain  string `json:"domain,omitempty"`
	CIDR    string `json:"cidr,omitempty"`
	Action  string `json:"action"`
}

func (stm *SplitTunnelManager) LoadAppRules(data string) error {
	if strings.TrimSpace(data) == "" {
		return nil
	}
	var in []appRule
	if err := json.Unmarshal([]byte(data), &in); err != nil {
		return fmt.Errorf("failed to parse app rules: %w", err)
	}

	byCountry := false
	converted := make([]SplitTunnelRule, 0, len(in))
	for _, r := range in {
		if r.Kind == "geoip" {
			byCountry = strings.EqualFold(r.Action, "DIRECT")
			continue
		}
		action := "tunnel"
		switch strings.ToUpper(r.Action) {
		case "DIRECT":
			action = "direct"
		case "REJECT", "BLOCK":
			continue
		}

		var kind, value string
		switch r.Kind {
		case "domain-suffix":
			kind, value = "domain", r.Suffix
		case "domain-exact":
			kind, value = "domain-exact", r.Domain
		case "domain-keyword":
			kind, value = "domain-keyword", r.Keyword
		case "ip-cidr":
			kind, value = "ip", r.CIDR
		}
		if value == "" {
			continue
		}
		converted = append(converted, SplitTunnelRule{
			Type: kind, Value: value, Action: action, Enabled: true, Priority: appRulePriority,
		})
	}

	stm.mu.Lock()
	stm.rules = append(stm.rules, converted...)
	sortRulesByPriority(stm.rules)
	stm.byCountry = byCountry
	stm.verdicts = nil
	stm.mu.Unlock()
	return nil
}

func matchesDomainRule(rule SplitTunnelRule, hostname string) bool {
	value := strings.ToLower(rule.Value)
	switch rule.Type {
	case "domain":
		return matchesDomainSuffix(hostname, value)
	case "domain-exact":
		return hostname == value
	case "domain-keyword":
		return strings.Contains(hostname, value)
	}
	return false
}

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
