package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"whispera/internal/logger"
)

var log = logger.Module("bridge")

type Config struct {
	AutoRegister      bool   `yaml:"auto_register"`
	Type              string `yaml:"type"`
	Provider          string `yaml:"provider"`
	Region            string `yaml:"region"`
	RegistrationToken string `yaml:"registration_token"`
	UpstreamServer    string `yaml:"-"`
	ListenPort        string `yaml:"-"`
	PublicKey         string `yaml:"-"`
}

type Registrar struct {
	config *Config
	client *http.Client
}

func NewRegistrar(cfg *Config) *Registrar {
	return &Registrar{
		config: cfg,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (r *Registrar) Register() error {
	if !r.config.AutoRegister {
		log.Printf("Auto-registration disabled, skipping")
		return nil
	}

	if r.config.UpstreamServer == "" {
		return fmt.Errorf("upstream server not configured")
	}

	if r.config.RegistrationToken == "" {
		return fmt.Errorf("registration token not configured")
	}

	publicIP := r.getPublicIP()
	if publicIP == "" {
		return fmt.Errorf("could not determine public IP")
	}

	address := fmt.Sprintf("%s:%s", publicIP, r.config.ListenPort)

	reqBody := map[string]string{
		"address":    address,
		"provider":   r.config.Provider,
		"region":     r.config.Region,
		"public_key": r.config.PublicKey,
		"type":       r.config.Type,
		"token":      r.config.RegistrationToken,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("https://%s/api/bridge-register", r.config.UpstreamServer)
	req1, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(data))
	req1.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req1)
	if err != nil {
		return fmt.Errorf("HTTPS registration failed (HTTP fallback disabled): %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registration failed: HTTP %d", resp.StatusCode)
	}

	var result struct {
		Success bool   `json:"success"`
		ID      string `json:"id"`
		Message string `json:"message"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if !result.Success {
		return fmt.Errorf("registration rejected: %s", result.Message)
	}

	log.Printf("✓ Bridge registered with main server: ID=%s, Address=%s", result.ID, address)
	return nil
}

func (r *Registrar) getPublicIP() string {
	services := []string{
		"https://ifconfig.me",
		"https://icanhazip.com",
		"https://api.ipify.org",
	}

	for _, svc := range services {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, svc, nil)
		resp, err := r.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		buf := make([]byte, 64)
		n, _ := resp.Body.Read(buf)
		ip := string(bytes.TrimSpace(buf[:n]))

		if net.ParseIP(ip) != nil {
			return ip
		}
	}

	if ip := os.Getenv("PUBLIC_IP"); ip != "" {
		return ip
	}

	return ""
}

func (r *Registrar) StartPeriodicHeartbeat(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			if err := r.Register(); err != nil {
				log.Printf("Heartbeat to main server failed: %v", err)
			}
		}
	}()
}
