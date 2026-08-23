package ipdetect

import (
	"context"
	"fmt"
	"net"
	"time"
)

func isPrivateIP(ip net.IP) bool {
	if ip.IsPrivate() {
		return true
	}
	ip4 := ip.To4()
	return ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127
}

func HostFromAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func DetectServerIP(ctx context.Context) (string, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if conn, err := (&net.Dialer{}).DialContext(dialCtx, "udp", "8.8.8.8:80"); err == nil {
		local, ok := conn.LocalAddr().(*net.UDPAddr)
		conn.Close()
		if ok && local.IP != nil && !isPrivateIP(local.IP) {
			return local.IP.String(), nil
		}
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			if !isPrivateIP(ip) {
				return ip.String(), nil
			}
		}
	}

	return "", fmt.Errorf("no public address on any interface: set server.public_url in the config")
}
