package dhcp

import (
	"fmt"
	"net"
	"sync"
)

type IPPool struct {
	mu sync.Mutex

	network   *net.IPNet
	networkIP net.IP
	broadcast net.IP

	usedIPs     map[string]bool
	reservedIPs map[string]bool

	nextIP uint32

	firstIP uint32
	lastIP  uint32
}

func (p *IPPool) Release(ip net.IP) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	ipStr := ip.String()

	if !p.usedIPs[ipStr] {
		return fmt.Errorf("IP %s is not in use", ipStr)
	}

	delete(p.usedIPs, ipStr)
	return nil
}

func (p *IPPool) AvailableCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	total := int(p.lastIP - p.firstIP + 1)
	used := len(p.usedIPs)
	reserved := len(p.reservedIPs)

	available := total - used - reserved
	if available < 0 {
		available = 0
	}
	return available
}

func (p *IPPool) UsedCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.usedIPs)
}

func (p *IPPool) TotalCount() int {
	return int(p.lastIP - p.firstIP + 1)
}
