package killswitch

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
)

const (
	rulePrefix     = "Whispera-KillSwitch"
	ruleAllowVPN   = rulePrefix + "-AllowVPN"
	ruleAllowLAN   = rulePrefix + "-AllowLAN"
	ruleAllowDNS   = rulePrefix + "-AllowDNS"
	ruleAllowLocal = rulePrefix + "-AllowLoopback"
)

type WindowsKillSwitch struct {
	mu          sync.Mutex
	rulesActive bool
	savedPolicy string
}

func NewPlatformImpl() (Platform, error) {
	return &WindowsKillSwitch{}, nil
}
func (w *WindowsKillSwitch) Name() string {
	return "windows"
}

func (w *WindowsKillSwitch) IsSupported() bool {
	cmd := exec.CommandContext(context.Background(), "netsh", "advfirewall", "show", "currentprofile")
	err := cmd.Run()
	return err == nil
}

func (w *WindowsKillSwitch) Enable(vpnServerIP net.IP, vpnPort int, allowLAN, allowDNS bool, allowedIPs []net.IP) (err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	defer func() {
		if err != nil {
			w.restorePolicy()
			w.cleanupRules()
			w.rulesActive = false
		}
	}()
	w.cleanupRules()
	w.savedPolicy = w.currentPolicy()
	if err = w.addRule(ruleAllowLocal, "in", "allow", "localip=127.0.0.1"); err != nil {
		return fmt.Errorf("failed to allow loopback in: %w", err)
	}
	if err = w.addRule(ruleAllowLocal+"-Out", "out", "allow", "localip=127.0.0.1"); err != nil {
		return fmt.Errorf("failed to allow loopback out: %w", err)
	}
	vpnIP := vpnServerIP.String()
	if err = w.addRule(ruleAllowVPN+"-In", "in", "allow", fmt.Sprintf("remoteip=%s", vpnIP)); err != nil {
		return fmt.Errorf("failed to allow VPN in: %w", err)
	}
	if err = w.addRule(ruleAllowVPN+"-Out", "out", "allow", fmt.Sprintf("remoteip=%s", vpnIP)); err != nil {
		return fmt.Errorf("failed to allow VPN out: %w", err)
	}
	if allowLAN {
		lanRanges := []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"169.254.0.0/16",
		}
		for i, cidr := range lanRanges {
			ruleName := fmt.Sprintf("%s-%d", ruleAllowLAN, i)
			w.tryRule(ruleName+"-In", "in", "allow", fmt.Sprintf("remoteip=%s", cidr))
			w.tryRule(ruleName+"-Out", "out", "allow", fmt.Sprintf("remoteip=%s", cidr))
		}
	}
	if allowDNS {
		w.tryRule(ruleAllowDNS+"-UDP-Out", "out", "allow", "protocol=udp remoteport=53")
		w.tryRule(ruleAllowDNS+"-TCP-Out", "out", "allow", "protocol=tcp remoteport=53")
	}
	for i, ip := range allowedIPs {
		ruleName := fmt.Sprintf("%s-Custom-%d", rulePrefix, i)
		ipStr := ip.String()
		w.tryRule(ruleName+"-In", "in", "allow", fmt.Sprintf("remoteip=%s", ipStr))
		w.tryRule(ruleName+"-Out", "out", "allow", fmt.Sprintf("remoteip=%s", ipStr))
	}
	if err = w.setPolicy("blockinbound,blockoutbound"); err != nil {
		return fmt.Errorf("failed to set blocking policy: %w", err)
	}

	w.rulesActive = true
	return nil
}

func (w *WindowsKillSwitch) Disable() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.restorePolicy()
	w.cleanupRules()
	w.rulesActive = false

	return nil
}

func (w *WindowsKillSwitch) currentPolicy() string {
	cmd := exec.CommandContext(context.Background(), "netsh", "advfirewall", "show", "currentprofile", "firewallpolicy")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(strings.ToLower(line), "firewallpolicy") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		policy := fields[len(fields)-1]
		if strings.Contains(policy, ",") {
			return policy
		}
	}
	return ""
}

func (w *WindowsKillSwitch) setPolicy(policy string) error {
	cmd := exec.CommandContext(context.Background(), "netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", policy)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("netsh set firewallpolicy %s: %v, output: %s", policy, err, string(out))
	}
	return nil
}

func (w *WindowsKillSwitch) restorePolicy() {
	policy := w.savedPolicy
	if policy == "" {
		policy = "blockinbound,allowoutbound"
	}
	if err := w.setPolicy(policy); err != nil {
		log.Warn("killswitch: restore firewall policy: %v", err)
	}
	w.savedPolicy = ""
}

func (w *WindowsKillSwitch) IsActive() (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.rulesActive, nil
}

func (w *WindowsKillSwitch) Cleanup() error {
	return w.Disable()
}
func (w *WindowsKillSwitch) tryRule(name, direction, action, extra string) {
	if err := w.addRule(name, direction, action, extra); err != nil {
		log.Warn("killswitch: rule %s: %v", name, err)
	}
}

func (w *WindowsKillSwitch) addRule(name, direction, action, extra string) error {
	args := []string{
		"advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%s", name),
		fmt.Sprintf("dir=%s", direction),
		fmt.Sprintf("action=%s", action),
	}

	if extra != "" {
		parts := strings.Fields(extra)
		args = append(args, parts...)
	}

	cmd := exec.CommandContext(context.Background(), "netsh", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh failed: %v, output: %s", err, string(output))
	}

	return nil
}

func (w *WindowsKillSwitch) cleanupRules() {
	cmd := exec.CommandContext(context.Background(), "netsh", "advfirewall", "firewall", "show", "rule", "name=all")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	rules := string(output)
	lines := strings.Split(rules, "\n")

	for _, line := range lines {
		if strings.Contains(line, "Rule Name:") && strings.Contains(line, rulePrefix) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				ruleName := strings.TrimSpace(parts[1])
				w.deleteRule(ruleName)
			}
		}
	}
}

func (w *WindowsKillSwitch) deleteRule(name string) {
	cmd := exec.CommandContext(context.Background(), "netsh", "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s", name))
	_ = cmd.Run()
}
