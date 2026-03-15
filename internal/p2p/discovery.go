package p2p

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"whispera/internal/util"
)

type DiscoveryService struct {
	mu           sync.RWMutex
	peers        map[string]*Node
	bootstrap    []string
	udpConn      *net.UDPConn
	running      bool
	listenAddr   string
	nodeID       string
	announcePort int
	hsPort       int
	signPriv     ed25519.PrivateKey
	signPub      ed25519.PublicKey
	ecdhPub      []byte
	ipLimits     map[string]*ipLimiter
	lastTS       map[string]int64
}

type ipLimiter struct {
	tokens     float64
	rate       float64
	burst      float64
	lastRefill time.Time
}

func (d *DiscoveryService) allowIP(ip string) bool {
	if d.ipLimits == nil {
		d.ipLimits = make(map[string]*ipLimiter)
	}
	lim, ok := d.ipLimits[ip]
	if !ok {
		lim = &ipLimiter{tokens: 10, rate: 10, burst: 20, lastRefill: time.Now()}
		d.ipLimits[ip] = lim
	}
	now := time.Now()
	dt := now.Sub(lim.lastRefill).Seconds()
	if dt > 0 {
		lim.tokens += dt * lim.rate
		if lim.tokens > lim.burst {
			lim.tokens = lim.burst
		}
		lim.lastRefill = now
	}
	if lim.tokens >= 1 {
		lim.tokens--
		return true
	}
	return false
}

type DiscoveryMessage struct {
	Type          string `json:"type"`
	NodeID        string `json:"node_id"`
	IP            string `json:"ip"`
	Port          int    `json:"port"`
	HandshakePort int    `json:"handshake_port,omitempty"`
	PublicKey     []byte `json:"public_key"`
	Timestamp     int64  `json:"timestamp"`
	SignPub       []byte `json:"sign_pub,omitempty"`
	ECDHPub       []byte `json:"ecdh_pub,omitempty"`
	Sig           []byte `json:"sig,omitempty"`
	Expire        int64  `json:"exp,omitempty"`
}

func (d *DiscoveryService) Start(ctx context.Context) {
	d.mu.Lock()
	d.running = true
	d.mu.Unlock()

	la := d.listenAddr
	if la == "" {
		la = ":51821"
	}
	addr, err := net.ResolveUDPAddr("udp", la)
	if err != nil {
		return
	}

	d.udpConn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return
	}
	defer util.SafeClose("udpConn", d.udpConn.Close)

	go d.handleMessages()

	go d.announceSelf(ctx)

	go d.discoverNodes(ctx)

	<-ctx.Done()

	d.mu.Lock()
	d.running = false
	d.mu.Unlock()
}

func (d *DiscoveryService) handleMessages() {
	buffer := make([]byte, 1024)

	for {
		d.mu.RLock()
		running := d.running
		d.mu.RUnlock()

		if !running {
			break
		}

		if err := d.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
			log.Debug("error setting read deadline: %v", err)
		}

		n, addr, err := d.udpConn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			continue
		}

		if !d.allowIP(addr.IP.String()) {
			continue
		}

		go d.processMessage(buffer[:n], addr)
	}
}

func (d *DiscoveryService) processMessage(data []byte, addr *net.UDPAddr) {
	var msg DiscoveryMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return
	}

	switch msg.Type {
	case "announce":
		d.handleAnnounce(&msg, addr)
	case "ping":
		d.handlePing(&msg, addr)
	case "pong":
		d.handlePong(&msg, addr)
	default:
	}
}

func (d *DiscoveryService) handleAnnounce(msg *DiscoveryMessage, addr *net.UDPAddr) {
	if len(msg.SignPub) > 0 && len(msg.Sig) > 0 {
		payload := struct {
			Type      string
			NodeID    string
			IP        string
			Port      int
			Timestamp int64
			ECDHPub   []byte
		}{
			Type:      msg.Type,
			NodeID:    msg.NodeID,
			IP:        addr.IP.String(),
			Port:      msg.Port,
			Timestamp: msg.Timestamp,
			ECDHPub:   msg.ECDHPub,
		}
		raw, _ := json.Marshal(payload)
		sum := sha256.Sum256(raw)
		if !ed25519.Verify(ed25519.PublicKey(msg.SignPub), sum[:], msg.Sig) {
			return
		}
		if time.Since(time.Unix(msg.Timestamp, 0)) > 5*time.Minute {
			return
		}
		if d.lastTS == nil {
			d.lastTS = make(map[string]int64)
		}
		d.mu.Lock()
		if last, ok := d.lastTS[msg.NodeID]; ok && msg.Timestamp <= last {
			d.mu.Unlock()
			return
		}
		d.lastTS[msg.NodeID] = msg.Timestamp
		d.mu.Unlock()
	} else {
		return
	}

	node := &Node{
		ID:            msg.NodeID,
		IP:            addr.IP.String(),
		Port:          msg.Port,
		HandshakePort: msg.HandshakePort,
		PublicKey:     firstNonNil(msg.ECDHPub, msg.PublicKey),
		LastSeen:      time.Now(),
	}

	d.mu.Lock()
	d.peers[msg.NodeID] = node
	d.mu.Unlock()

	d.sendPong(addr)
}

func (d *DiscoveryService) handlePing(msg *DiscoveryMessage, addr *net.UDPAddr) {
	if len(msg.SignPub) == 0 || len(msg.Sig) == 0 {
		return
	}
	payload := struct {
		Type      string
		NodeID    string
		IP        string
		Port      int
		Timestamp int64
		ECDHPub   []byte
	}{Type: msg.Type, NodeID: msg.NodeID, IP: "", Port: 0, Timestamp: msg.Timestamp, ECDHPub: msg.ECDHPub}
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	if !ed25519.Verify(ed25519.PublicKey(msg.SignPub), sum[:], msg.Sig) {
		return
	}
	if time.Since(time.Unix(msg.Timestamp, 0)) > 5*time.Minute {
		return
	}
	if d.lastTS == nil {
		d.lastTS = make(map[string]int64)
	}
	d.mu.Lock()
	if last, ok := d.lastTS[msg.NodeID]; ok && msg.Timestamp <= last {
		d.mu.Unlock()
		return
	}
	d.lastTS[msg.NodeID] = msg.Timestamp
	d.mu.Unlock()

	d.mu.Lock()
	if peer, exists := d.peers[msg.NodeID]; exists {
		peer.LastSeen = time.Now()
		peer.IP = addr.IP.String()
	}
	d.mu.Unlock()

	d.sendPong(addr)
}

func (d *DiscoveryService) handlePong(msg *DiscoveryMessage, addr *net.UDPAddr) {
	if len(msg.SignPub) == 0 || len(msg.Sig) == 0 {
		return
	}
	payload := struct {
		Type      string
		NodeID    string
		IP        string
		Port      int
		Timestamp int64
		ECDHPub   []byte
	}{Type: msg.Type, NodeID: msg.NodeID, IP: "", Port: 0, Timestamp: msg.Timestamp, ECDHPub: msg.ECDHPub}
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	if !ed25519.Verify(ed25519.PublicKey(msg.SignPub), sum[:], msg.Sig) {
		return
	}
	if time.Since(time.Unix(msg.Timestamp, 0)) > 5*time.Minute {
		return
	}
	if d.lastTS == nil {
		d.lastTS = make(map[string]int64)
	}
	d.mu.Lock()
	if last, ok := d.lastTS[msg.NodeID]; ok && msg.Timestamp <= last {
		d.mu.Unlock()
		return
	}
	d.lastTS[msg.NodeID] = msg.Timestamp
	d.mu.Unlock()

	d.mu.Lock()
	if peer, exists := d.peers[msg.NodeID]; exists {
		peer.LastSeen = time.Now()
	} else {
		valid := false
		if len(msg.SignPub) > 0 && len(msg.Sig) > 0 && len(msg.ECDHPub) == 32 {
			payload := struct {
				Type      string
				NodeID    string
				IP        string
				Port      int
				Timestamp int64
				ECDHPub   []byte
			}{
				Type:      msg.Type,
				NodeID:    msg.NodeID,
				IP:        addr.IP.String(),
				Port:      msg.Port,
				Timestamp: msg.Timestamp,
				ECDHPub:   msg.ECDHPub,
			}
			raw, _ := json.Marshal(payload)
			sum := sha256.Sum256(raw)
			if ed25519.Verify(ed25519.PublicKey(msg.SignPub), sum[:], msg.Sig) {
				valid = true
			}
		}
		if valid {
			d.peers[msg.NodeID] = &Node{
				ID:        msg.NodeID,
				IP:        addr.IP.String(),
				Port:      51821,
				PublicKey: msg.ECDHPub,
				LastSeen:  time.Now(),
			}
		}
	}
	d.mu.Unlock()
}

func (d *DiscoveryService) announceSelf(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.broadcastAnnounce()
		}
	}
}

func (d *DiscoveryService) broadcastAnnounce() {
	port := d.announcePort
	if port == 0 {
		port = 51821
		if d.udpConn != nil {
			if la, ok := d.udpConn.LocalAddr().(*net.UDPAddr); ok {
				if la.Port != 0 {
					port = la.Port
				}
			}
		} else if d.listenAddr != "" {
			if a, err := net.ResolveUDPAddr("udp", d.listenAddr); err == nil && a.Port != 0 {
				port = a.Port
			}
		}
	}
	msg := DiscoveryMessage{
		Type:          "announce",
		NodeID:        d.nodeID,
		IP:            d.getMyIP(),
		Port:          port,
		HandshakePort: d.hsPort,
		Timestamp:     time.Now().Unix(),
		SignPub:       d.signPub,
		ECDHPub:       d.ecdhPub,
	}
	payload := struct {
		Type      string
		NodeID    string
		IP        string
		Port      int
		Timestamp int64
		ECDHPub   []byte
	}{Type: msg.Type, NodeID: msg.NodeID, IP: msg.IP, Port: msg.Port, Timestamp: msg.Timestamp, ECDHPub: msg.ECDHPub}
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	if d.signPriv != nil {
		msg.Sig = ed25519.Sign(d.signPriv, sum[:])
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return
	}

	d.mu.RLock()
	for _, peer := range d.peers {
		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", peer.IP, peer.Port))
		if err != nil {
			continue
		}

		if _, err := d.udpConn.WriteToUDP(data, addr); err != nil {
			log.Debug("error writing to UDP: %v", err)
		}
	}
	d.mu.RUnlock()
}

func (d *DiscoveryService) discoverNodes(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.pingBootstrapNodes()
		}
	}
}

func (d *DiscoveryService) pingBootstrapNodes() {
	msg := DiscoveryMessage{
		Type:      "ping",
		NodeID:    d.nodeID,
		Timestamp: time.Now().Unix(),
		SignPub:   d.signPub,
		ECDHPub:   d.ecdhPub,
	}
	payload := struct {
		Type      string
		NodeID    string
		IP        string
		Port      int
		Timestamp int64
		ECDHPub   []byte
	}{Type: msg.Type, NodeID: msg.NodeID, IP: "", Port: 0, Timestamp: msg.Timestamp, ECDHPub: msg.ECDHPub}
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	if d.signPriv != nil {
		msg.Sig = ed25519.Sign(d.signPriv, sum[:])
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return
	}

	for _, bootstrap := range d.bootstrap {
		addr, err := net.ResolveUDPAddr("udp", bootstrap)
		if err != nil {
			continue
		}

		if _, err := d.udpConn.WriteToUDP(data, addr); err != nil {
			log.Debug("error writing to UDP: %v", err)
		}
	}
}

func (d *DiscoveryService) sendPong(addr *net.UDPAddr) {
	if d.udpConn == nil {
		return
	}

	msg := DiscoveryMessage{
		Type:      "pong",
		NodeID:    d.nodeID,
		Timestamp: time.Now().Unix(),
		SignPub:   d.signPub,
		ECDHPub:   d.ecdhPub,
	}
	payload := struct {
		Type      string
		NodeID    string
		IP        string
		Port      int
		Timestamp int64
		ECDHPub   []byte
	}{
		Type:      msg.Type,
		NodeID:    msg.NodeID,
		IP:        addr.IP.String(),
		Port:      addr.Port,
		Timestamp: msg.Timestamp,
		ECDHPub:   msg.ECDHPub,
	}
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	if d.signPriv != nil {
		msg.Sig = ed25519.Sign(d.signPriv, sum[:])
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return
	}

	if _, err := d.udpConn.WriteToUDP(data, addr); err != nil {
		log.Debug("Error writing UDP: %v", err)
	}
}

func firstNonNil(a, b []byte) []byte {
	if len(a) > 0 {
		return a
	}
	return b
}

func (d *DiscoveryService) getMyIP() string {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	ctx := context.Background()
	conn, err := dialer.DialContext(ctx, "udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer util.SafeClose("conn", conn.Close)

	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func (d *DiscoveryService) GetPeers() []*Node {
	d.mu.RLock()
	defer d.mu.RUnlock()

	peers := make([]*Node, 0, len(d.peers))
	for _, peer := range d.peers {
		if time.Since(peer.LastSeen) < 5*time.Minute {
			peers = append(peers, peer)
		}
	}

	return peers
}

func (d *DiscoveryService) GetPeerCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return len(d.peers)
}
