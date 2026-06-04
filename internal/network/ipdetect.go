package network

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type IPDetector struct {
	mu         sync.RWMutex
	cachedIP   string
	lastCheck  time.Time
	cacheTTL   time.Duration
	httpClient *http.Client
}

type IPDetectConfig struct {
	CacheTTL       time.Duration
	RequestTimeout time.Duration
	PreferIPv4     bool
}

func DefaultIPDetectConfig() *IPDetectConfig {
	return &IPDetectConfig{
		CacheTTL:       5 * time.Minute,
		RequestTimeout: 10 * time.Second,
		PreferIPv4:     true,
	}
}

func NewIPDetector(cfg *IPDetectConfig) *IPDetector {
	if cfg == nil {
		cfg = DefaultIPDetectConfig()
	}

	return &IPDetector{
		cacheTTL: cfg.CacheTTL,
		httpClient: &http.Client{
			Timeout: cfg.RequestTimeout,
		},
	}
}

type externalIPService struct {
	URL       string
	ParseFunc func(body []byte) (string, error)
}

var ipServices = []externalIPService{
	{
		URL: "https://api.ipify.org?format=json",
		ParseFunc: func(body []byte) (string, error) {
			var result struct {
				IP string `json:"ip"`
			}
			if err := json.Unmarshal(body, &result); err != nil {
				return "", err
			}
			return result.IP, nil
		},
	},
	{
		URL: "https://ifconfig.me/ip",
		ParseFunc: func(body []byte) (string, error) {
			return strings.TrimSpace(string(body)), nil
		},
	},
	{
		URL: "https://icanhazip.com",
		ParseFunc: func(body []byte) (string, error) {
			return strings.TrimSpace(string(body)), nil
		},
	},
	{
		URL: "https://checkip.amazonaws.com",
		ParseFunc: func(body []byte) (string, error) {
			return strings.TrimSpace(string(body)), nil
		},
	},
	{
		URL: "https://2ip.ru/api/self",
		ParseFunc: func(body []byte) (string, error) {
			var result struct {
				IP string `json:"ip"`
			}
			if err := json.Unmarshal(body, &result); err != nil {
				return strings.TrimSpace(string(body)), nil
			}
			return result.IP, nil
		},
	},
}

func (d *IPDetector) DetectExternalIP(ctx context.Context) (string, error) {
	d.mu.RLock()
	if d.cachedIP != "" && time.Since(d.lastCheck) < d.cacheTTL {
		ip := d.cachedIP
		d.mu.RUnlock()
		return ip, nil
	}
	d.mu.RUnlock()

	ip, err := d.detectFromExternalServices(ctx)
	if err == nil && ip != "" {
		d.cacheIP(ip)
		return ip, nil
	}

	ip, err = d.detectFromLocalInterfaces()
	if err == nil && ip != "" {
		d.cacheIP(ip)
		return ip, nil
	}

	d.mu.RLock()
	if d.cachedIP != "" {
		ip := d.cachedIP
		d.mu.RUnlock()
		return ip, nil
	}
	d.mu.RUnlock()

	return "", fmt.Errorf("failed to detect external IP: %w", err)
}

func (d *IPDetector) detectFromExternalServices(ctx context.Context) (string, error) {
	var lastErr error

	for _, service := range ipServices {
		ip, err := d.queryService(ctx, service)
		if err != nil {
			lastErr = err
			continue
		}

		if parsedIP := net.ParseIP(ip); parsedIP != nil {
			return ip, nil
		}
	}

	return "", fmt.Errorf("all external services failed: %v", lastErr)
}

func (d *IPDetector) queryService(ctx context.Context, service externalIPService) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", service.URL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", "Whispera/1.0")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("service returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return "", err
	}

	return service.ParseFunc(body)
}

func (d *IPDetector) detectFromLocalInterfaces() (string, error) {
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(context.Background(), "udp", "8.8.8.8:80")
	if err == nil {
		defer conn.Close()
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		return localAddr.IP.String(), nil
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

	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
				return ip.String(), nil
			}
		}
	}

	return "", fmt.Errorf("no suitable interface found")
}

func (d *IPDetector) cacheIP(ip string) {
	d.mu.Lock()
	d.cachedIP = ip
	d.lastCheck = time.Now()
	d.mu.Unlock()
}

func isPrivateIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 10 {
			return true
		}
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
	}
	return false
}

var globalDetector *IPDetector
var globalDetectorOnce sync.Once

func GetGlobalDetector() *IPDetector {
	globalDetectorOnce.Do(func() {
		globalDetector = NewIPDetector(nil)
	})
	return globalDetector
}

func DetectServerIP(ctx context.Context) (string, error) {
	return GetGlobalDetector().DetectExternalIP(ctx)
}

type ServerInfo struct {
	ExternalIP string          `json:"external_ip"`
	Hostname   string          `json:"hostname"`
	Interfaces []InterfaceInfo `json:"interfaces"`
	DetectedAt time.Time       `json:"detected_at"`
}

type InterfaceInfo struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	IsUp      bool     `json:"is_up"`
}
