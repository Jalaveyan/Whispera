package apiserver

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
)

func isTrustedProxy(ip string) bool {
	trusted := []string{
		"127.0.0.0/8",
		"::1/128",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range trusted {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

func (s *Server) getClientIP(r *http.Request) string {
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !isTrustedProxy(remoteIP) {
		return remoteIP
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			if ip != "" && !isTrustedProxy(ip) {
				return ip
			}
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	return remoteIP
}

func (s *Server) IsKeyRevoked(keyID string) bool {
	if keyID == "" {
		return false
	}
	s.revokedKeysMu.RLock()
	_, revoked := s.revokedKeys[keyID]
	s.revokedKeysMu.RUnlock()
	return revoked
}

func (s *Server) loadRevokedKeys() {
	data, err := os.ReadFile("/etc/whispera/revoked_keys.json")
	if err != nil {
		return
	}
	s.revokedKeysMu.Lock()
	_ = json.Unmarshal(data, &s.revokedKeys)
	s.revokedKeysMu.Unlock()
}
