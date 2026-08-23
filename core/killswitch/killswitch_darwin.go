package killswitch

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
)

const (
	pfConfPath  = "/tmp/whispera_killswitch.conf"
	pfSavedPath = "/tmp/whispera_killswitch_saved.conf"
	anchorName  = "whispera_killswitch"
	anchorLine  = `anchor "whispera_killswitch"`
)

type DarwinKillSwitch struct {
	mu          sync.Mutex
	rulesActive bool
	savedRules  string
	wasEnabled  bool
}

func NewPlatformImpl() (Platform, error) {
	return &DarwinKillSwitch{}, nil
}

func (d *DarwinKillSwitch) Name() string {
	return "darwin"
}

func (d *DarwinKillSwitch) IsSupported() bool {
	cmd := exec.CommandContext(context.Background(), "pfctl", "-s", "info")
	return cmd.Run() == nil
}

func (d *DarwinKillSwitch) Enable(vpnServerIP net.IP, vpnPort int, allowLAN, allowDNS bool, allowedIPs []net.IP) (err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	defer func() {
		if err != nil {
			_ = d.disableLocked()
		}
	}()

	if out, perr := d.pfctlOutput("-s", "info"); perr == nil {
		d.wasEnabled = strings.Contains(out, "Status: Enabled")
	}
	if out, perr := d.pfctlOutput("-s", "rules"); perr == nil {
		d.savedRules = out
	}

	var rules strings.Builder
	rules.WriteString("pass quick on lo0 all\n")
	vpnIP := vpnServerIP.String()
	rules.WriteString(fmt.Sprintf("pass out quick to %s\n", vpnIP))
	rules.WriteString(fmt.Sprintf("pass in quick from %s\n", vpnIP))
	if allowLAN {
		for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"} {
			rules.WriteString(fmt.Sprintf("pass quick to %s\n", cidr))
			rules.WriteString(fmt.Sprintf("pass quick from %s\n", cidr))
		}
	}
	if allowDNS {
		rules.WriteString("pass out quick proto udp to any port 53\n")
		rules.WriteString("pass out quick proto tcp to any port 53\n")
	}
	for _, ip := range allowedIPs {
		rules.WriteString(fmt.Sprintf("pass quick to %s\n", ip.String()))
		rules.WriteString(fmt.Sprintf("pass quick from %s\n", ip.String()))
	}
	for _, iface := range []string{"utun0", "utun1", "utun2", "utun3"} {
		rules.WriteString(fmt.Sprintf("pass quick on %s all\n", iface))
	}
	rules.WriteString("block drop quick all\n")

	if err = writePrivate(pfConfPath, rules.String()); err != nil {
		return fmt.Errorf("write pf rules: %w", err)
	}
	if err = d.runPfctl("-a", anchorName, "-f", pfConfPath); err != nil {
		return fmt.Errorf("load pf anchor: %w", err)
	}

	main := d.savedRules
	if !strings.Contains(main, anchorLine) {
		if main != "" && !strings.HasSuffix(main, "\n") {
			main += "\n"
		}
		main += anchorLine + "\n"
	}
	if err = writePrivate(pfSavedPath, main); err != nil {
		return fmt.Errorf("write pf main ruleset: %w", err)
	}
	if err = d.runPfctl("-f", pfSavedPath); err != nil {
		return fmt.Errorf("load pf main ruleset: %w", err)
	}
	if err = d.runPfctl("-e"); err != nil && !strings.Contains(err.Error(), "already enabled") {
		return fmt.Errorf("enable pf: %w", err)
	}

	d.rulesActive = true
	return nil
}

func (d *DarwinKillSwitch) Disable() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.disableLocked()
}

func (d *DarwinKillSwitch) disableLocked() error {
	var firstErr error
	if err := d.runPfctl("-a", anchorName, "-F", "all"); err != nil {
		firstErr = err
	}
	if d.savedRules != "" {
		if err := writePrivate(pfSavedPath, d.savedRules); err == nil {
			if err := d.runPfctl("-f", pfSavedPath); err != nil && firstErr == nil {
				firstErr = err
			}
		} else if firstErr == nil {
			firstErr = err
		}
	}
	if !d.wasEnabled {
		if err := d.runPfctl("-d"); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	_ = os.Remove(pfConfPath)
	_ = os.Remove(pfSavedPath)
	d.rulesActive = false
	return firstErr
}

func (d *DarwinKillSwitch) IsActive() (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.rulesActive, nil
}

func (d *DarwinKillSwitch) Cleanup() error {
	return d.Disable()
}

func (d *DarwinKillSwitch) runPfctl(args ...string) error {
	_, err := d.pfctlOutput(args...)
	return err
}

func (d *DarwinKillSwitch) pfctlOutput(args ...string) (string, error) {
	cmd := exec.CommandContext(context.Background(), "pfctl", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("pfctl %s: %v, output: %s", strings.Join(args, " "), err, string(output))
	}
	return string(output), nil
}

func writePrivate(path, content string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(content)
	return err
}
