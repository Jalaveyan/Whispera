package apiserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/nekoskin/whispera/common/fsown"
	"github.com/nekoskin/whispera/common/ipdetect"
	"github.com/nekoskin/whispera/core/config"

	"golang.org/x/crypto/curve25519"
)

type Subscription struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Group      string    `json:"group,omitempty"`
	Token      string    `json:"token"`
	UserIDs    []int     `json:"user_ids"`
	KeyIDs     []string  `json:"key_ids,omitempty"`
	Transports []string  `json:"transports"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	SubURL     string    `json:"sub_url,omitempty"`
}

const subDataFile = "/etc/whispera/subscriptions.json"

var (
	subStoreMu sync.RWMutex
	subStore   = make(map[string]*Subscription)
	subByToken = make(map[string]*Subscription)
	subNextID  int
)

type subPersist struct {
	Subscriptions []*Subscription `json:"subscriptions"`
	NextID        int             `json:"next_id"`
}

func saveSubscriptions() {
	subStoreMu.RLock()
	list := make([]*Subscription, 0, len(subStore))
	for _, s := range subStore {
		list = append(list, s)
	}
	nid := subNextID
	subStoreMu.RUnlock()

	data, err := json.Marshal(subPersist{Subscriptions: list, NextID: nid})
	if err != nil {
		log.Error("failed to marshal subscriptions: %v", err)
		return
	}
	if err := fsown.WriteFile(subDataFile, data, 0600); err != nil {
		log.Error("failed to save subscriptions: %v", err)
	}
}

func loadSubscriptions() {
	data, err := os.ReadFile(subDataFile)
	if err != nil {
		return
	}
	var p subPersist
	if err := json.Unmarshal(data, &p); err != nil {
		log.Error("failed to load subscriptions: %v", err)
		return
	}
	subStoreMu.Lock()
	for _, s := range p.Subscriptions {
		subStore[s.ID] = s
		subByToken[s.Token] = s
	}
	if p.NextID > subNextID {
		subNextID = p.NextID
	}
	subStoreMu.Unlock()
}

func (s *Server) subscriptionServers(ctx context.Context, transports []string) []map[string]interface{} {
	provider, ok := configProviderAs[interface{ GetConfig() *config.ServerConfig }](s)
	if !ok {
		return nil
	}

	cfg := provider.GetConfig()
	addr := config.HostFromPublicURL(cfg.Server.PublicURL)
	if addr == "" {
		detectCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		addr, _ = ipdetect.DetectServerIP(detectCtx)
		cancel()
	}
	return buildServerList(cfg, addr, transports)
}

func subscriptionKeys(sub *Subscription) []string {
	userStoreMu.RLock()
	defer userStoreMu.RUnlock()

	var keys []string
	switch {
	case len(sub.KeyIDs) > 0:
		wanted := make(map[string]bool, len(sub.KeyIDs))
		for _, kid := range sub.KeyIDs {
			wanted[kid] = true
		}
		for _, u := range userStore {
			if u.ConnectionURI != "" && wanted[u.ConnectionURI] {
				keys = append(keys, u.ConnectionURI)
			}
		}
	case len(sub.UserIDs) > 0:
		for _, uid := range sub.UserIDs {
			if u, ok := userStore[uid]; ok && u.ConnectionURI != "" {
				keys = append(keys, u.ConnectionURI)
			}
		}
	default:
		for _, u := range userStore {
			if u.ConnectionURI != "" {
				keys = append(keys, u.ConnectionURI)
			}
		}
	}
	return keys
}

func (s *Server) handleServeSubscription(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if token == "" {
		http.NotFound(w, r)
		return
	}

	subStoreMu.RLock()
	sub, ok := subByToken[token]
	subStoreMu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}

	raw, err := json.Marshal(map[string]interface{}{
		"version": "2",
		"name":    sub.Name,
		"updated": sub.UpdatedAt.UTC().Format(time.RFC3339),
		"servers": s.subscriptionServers(r.Context(), sub.Transports),
		"keys":    subscriptionKeys(sub),
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="whispera-sub.txt"`)
	w.Header().Set("Profile-Update-Interval", "24")
	fmt.Fprint(w, base64.StdEncoding.EncodeToString(raw))
}

func buildServerList(cfg *config.ServerConfig, serverIP string, preferredTransports []string) []map[string]interface{} {
	if cfg == nil {
		return nil
	}

	transportSet := make(map[string]bool)
	for _, t := range preferredTransports {
		transportSet[t] = true
	}

	var servers []map[string]interface{}

	for _, inbound := range cfg.Inbounds {
		network := inbound.StreamSettings.Network
		if network == "" {
			network = "tcp"
		}

		if len(transportSet) > 0 && !transportSet[network] {
			continue
		}

		entry := map[string]interface{}{
			"name":      inbound.Tag,
			"address":   serverIP,
			"port":      inbound.Port,
			"transport": network,
			"security":  inbound.StreamSettings.Security,
		}

		if len(inbound.Ports) > 0 {
			entry["ports"] = inbound.AllPorts()
		}

		if inbound.StreamSettings.WS.Path != "" {
			entry["ws_path"] = inbound.StreamSettings.WS.Path
		}

		for k, v := range inbound.StreamSettings.Params {
			if _, exists := entry[k]; !exists {
				entry[k] = v
			}
		}

		servers = append(servers, entry)
	}

	if cfg.Whispera.Enabled && cfg.Whispera.ListenAddr != "" && (len(transportSet) == 0 || transportSet["whispera"]) {
		port := config.PortFromListenAddr(cfg.Whispera.ListenAddr)
		cEntry := map[string]interface{}{
			"name":      "whispera",
			"address":   serverIP,
			"port":      port,
			"transport": "whispera",
		}
		if cfg.Whispera.Domain != "" {
			cEntry["sni"] = cfg.Whispera.Domain
		}
		servers = append(servers, cEntry)
	}

	if cfg.Transport.TCP.Enabled && (len(transportSet) == 0 || transportSet["tcp"]) {
		port := config.PortFromListenAddr(cfg.Transport.TCP.ListenAddr)
		servers = append(servers, map[string]interface{}{
			"name":      "tcp",
			"address":   serverIP,
			"port":      port,
			"transport": "tcp",
		})
	}

	return servers
}

func derivePublicKeyB64(privKeyB64 string) string {
	b, err := base64.StdEncoding.DecodeString(privKeyB64)
	if err != nil || len(b) != 32 {
		return ""
	}
	var priv [32]byte
	copy(priv[:], b)
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(pub)
}
