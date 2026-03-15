package p2p

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"whispera/internal/handshake"
	"whispera/internal/logger"
	"whispera/internal/util"

	"golang.org/x/crypto/curve25519"
)

var log = logger.Module("p2p")

type P2PNetwork struct {
	mu              sync.RWMutex
	nodes           map[string]*Node
	bootstrap       []string
	myNode          *Node
	discovery       *DiscoveryService
	routing         *RoutingEngine
	consensus       *ConsensusEngine
	encryption      *P2PEncryption
	sessions        map[string]string
	DiscoveryListen string
	udpConn         *net.UDPConn
	p2pTx           int64
	p2pRx           int64
	signPriv        ed25519.PrivateKey
	signPub         ed25519.PublicKey
	ecdhPriv        []byte
	ecdhPub         []byte
}

type Node struct {
	ID            string        `json:"id"`
	IP            string        `json:"ip"`
	Port          int           `json:"port"`
	HandshakePort int           `json:"handshake_port"`
	PublicKey     []byte        `json:"public_key"`
	LastSeen      time.Time     `json:"last_seen"`
	Latency       time.Duration `json:"latency"`
	Reliability   float64       `json:"reliability"`
	Capabilities  []string      `json:"capabilities"`
}

func NewP2PNetwork(bootstrap []string) *P2PNetwork {
	return &P2PNetwork{
		nodes:     make(map[string]*Node),
		bootstrap: bootstrap,
		discovery: &DiscoveryService{
			peers:     make(map[string]*Node),
			bootstrap: bootstrap,
		},
		routing:    NewRoutingEngine("my-node-id"),
		consensus:  NewConsensusEngine(),
		encryption: NewP2PEncryption(),
		sessions:   make(map[string]string),
	}
}

func (p *P2PNetwork) Start(ctx context.Context) error {
	p.myNode = p.createMyNode()
	_ = p.myNode

	if p.DiscoveryListen != "" {
		p.discovery.listenAddr = p.DiscoveryListen
	}
	if p.myNode != nil {
		p.discovery.nodeID = p.myNode.ID
		p.discovery.signPriv = p.signPriv
		p.discovery.signPub = p.signPub
		p.discovery.ecdhPub = p.ecdhPub
	}
	go p.discovery.Start(ctx)
	go p.routing.Start(ctx)
	go p.consensus.Start(ctx)
	go p.encryption.Start(ctx)

	go p.syncPeersLoop(ctx)

	go p.startUDPTransport(ctx)

	go p.startHandshakeListener(ctx)

	for _, bootstrap := range p.bootstrap {
		go p.connectToBootstrap(bootstrap)
	}

	return nil
}

func (p *P2PNetwork) createMyNode() *Node {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		log.Error("Error generating node ID: %v", err)
		return nil
	}

	if p.signPriv == nil || p.signPub == nil {
		spub, spriv, _ := ed25519.GenerateKey(rand.Reader)
		p.signPriv = spriv
		p.signPub = spub
	}
	if p.ecdhPriv == nil || p.ecdhPub == nil {
		priv := make([]byte, 32)
		if _, err := rand.Read(priv); err != nil {
			log.Error("Error generating ECDH key: %v", err)
			return nil
		}
		pub, _ := curve25519.X25519(priv, curve25519.Basepoint)
		p.ecdhPriv = priv
		p.ecdhPub = pub
	}

	return &Node{
		ID:            fmt.Sprintf("%x", id),
		IP:            p.getMyIP(),
		Port:          51820,
		HandshakePort: 0,
		LastSeen:      time.Now(),
		Reliability:   1.0,
		Capabilities:  []string{"vpn", "obfuscation", "speedtest"},
		PublicKey:     p.ecdhPub,
	}
}

func (p *P2PNetwork) getMyIP() string {
	d := &net.Dialer{Timeout: 2 * time.Second}
	ctx := context.Background()
	conn, err := d.DialContext(ctx, "udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer util.SafeClose("conn", conn.Close)

	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func (p *P2PNetwork) connectToBootstrap(bootstrap string) {

}

func (p *P2PNetwork) FindBestRoute(destination string) (*Route, error) {
	return p.routing.FindBestRoute(destination)
}

func (p *P2PNetwork) BroadcastMessage(message []byte) error {
	return nil
}

func (p *P2PNetwork) GetAvailableNodes() []*Node {
	p.mu.RLock()
	defer p.mu.RUnlock()

	nodes := make([]*Node, 0, len(p.nodes))
	for _, node := range p.nodes {
		if time.Since(node.LastSeen) < 5*time.Minute {
			nodes = append(nodes, node)
		}
	}

	return nodes
}

func (p *P2PNetwork) AddNode(node *Node) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.nodes[node.ID] = node

	if p.routing != nil {
		p.routing.AddNode(node)
	}
	if p.consensus != nil {
		participant := &Participant{
			ID:         node.ID,
			Weight:     1.0,
			LastSeen:   time.Now(),
			Reputation: 1.0,
			Stake:      0,
			Active:     true,
		}
		p.consensus.AddParticipant(participant)
	}
}

func (p *P2PNetwork) RemoveNode(nodeID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	delete(p.nodes, nodeID)

	if p.routing != nil {
		p.routing.RemoveNode(nodeID)
	}
	if p.consensus != nil {
		p.consensus.RemoveParticipant(nodeID)
	}
	if p.sessions != nil {
		delete(p.sessions, nodeID)
	}
}

func (p *P2PNetwork) GetNetworkStats() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := map[string]interface{}{
		"total_nodes":     len(p.nodes),
		"active_nodes":    len(p.GetAvailableNodes()),
		"bootstrap_nodes": len(p.bootstrap),
	}

	if p.myNode != nil {
		stats["my_node_id"] = p.myNode.ID
		stats["my_ip"] = p.myNode.IP
	} else {
		stats["my_node_id"] = ""
		stats["my_ip"] = ""
	}

	if p.routing != nil {
		stats["routing"] = p.routing.GetRoutingStats()
	}
	if p.consensus != nil {
		stats["consensus"] = p.consensus.GetConsensusStats()
	}
	if p.encryption != nil {
		stats["encryption"] = p.encryption.GetEncryptionStats()
	}
	stats["p2p_tx"] = p.p2pTx
	stats["p2p_rx"] = p.p2pRx

	return stats
}

func (p *P2PNetwork) syncPeersLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			peers := p.discovery.GetPeers()
			for _, peer := range peers {
				p.mu.RLock()
				_, exists := p.nodes[peer.ID]
				p.mu.RUnlock()
				if !exists {
					p.AddNode(peer)
					if p.routing != nil {
						p.routing.AddNode(&Node{
							ID:          peer.ID,
							IP:          peer.IP,
							Port:        peer.Port,
							Latency:     peer.Latency,
							Reliability: peer.Reliability,
							LastSeen:    peer.LastSeen,
						})
					}
				} else {
					p.mu.Lock()
					if n, ok := p.nodes[peer.ID]; ok {
						n.LastSeen = time.Now()
						n.IP = peer.IP
						n.Port = peer.Port
						n.Latency = peer.Latency
						n.Reliability = peer.Reliability
					}
					p.mu.Unlock()
				}
			}
		}
	}
}

func (p *P2PNetwork) ensureSession(nodeID string) (string, error) {
	p.mu.RLock()
	if sid, ok := p.sessions[nodeID]; ok && p.encryption.ValidateSession(sid) {
		p.mu.RUnlock()
		return sid, nil
	}
	p.mu.RUnlock()

	myID := ""
	if p.myNode != nil {
		myID = p.myNode.ID
	}
	p.discovery.mu.RLock()
	peer := p.discovery.peers[nodeID]
	p.discovery.mu.RUnlock()
	if peer == nil || len(peer.PublicKey) != 32 {
		return "", fmt.Errorf("peer pubkey missing")
	}
	hsPort := peer.HandshakePort
	if hsPort == 0 {
		hsPort = peer.Port
	}
	raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", peer.IP, hsPort))
	if err != nil {
		return "", err
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return "", err
	}
	defer util.SafeClose("conn", conn.Close)
	seed, _, err := handshake.ClientIK(conn, raddr, peer.PublicKey, "")
	if err != nil {
		return "", err
	}
	session, err := p.encryption.CreateECDHSessionForPeers(myID, nodeID, seed)
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	p.sessions[nodeID] = session.ID
	p.mu.Unlock()
	return session.ID, nil
}

func (p *P2PNetwork) SendSecureMessage(nodeID string, data []byte) (*EncryptedMessage, error) {
	sid, err := p.ensureSession(nodeID)
	if err != nil {
		return nil, err
	}
	enc, err := p.encryption.EncryptMessage(sid, data)
	if err != nil {
		return nil, err
	}
	if p.udpConn != nil {
		p.discovery.mu.RLock()
		peer := p.discovery.peers[nodeID]
		p.discovery.mu.RUnlock()
		if peer != nil {
			ip := peer.IP
			port := peer.Port
			if port == 0 {
				port = 51821
			}
			addr, rerr := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip, port))
			if rerr == nil {
				if p.myNode != nil {
					enc.FromNode = p.myNode.ID
				}
				payload, mErr := json.Marshal(enc)
				if mErr == nil {
					_, _ = p.udpConn.WriteToUDP(payload, addr)
					p.p2pTx++
				}
			}
		}
	}
	return enc, nil
}

func (p *P2PNetwork) ReceiveSecureMessage(msg *EncryptedMessage) ([]byte, error) {
	plaintext, err := p.encryption.DecryptMessage(msg)
	if err != nil {
		return nil, err
	}
	if len(plaintext) > 0 {
		_ = plaintext
	}
	return plaintext, nil
}

func (p *P2PNetwork) startUDPTransport(ctx context.Context) {
	laddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return
	}
	p.udpConn = conn
	if la, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		if p.discovery != nil {
			p.discovery.announcePort = la.Port
			go p.discovery.broadcastAnnounce()
		}
	}
	buf := make([]byte, 65535)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					_ = conn.Close()
					return
				default:
				}
				continue
			}
			continue
		}
		var em EncryptedMessage
		if uerr := json.Unmarshal(buf[:n], &em); uerr != nil {
			continue
		}
		if p.myNode != nil && em.FromNode != "" {
			if _, ok := p.sessions[em.FromNode]; !ok {
				if s, err := p.encryption.CreateSharedSessionForPeers(p.myNode.ID, em.FromNode); err == nil {
					p.sessions[em.FromNode] = s.ID
				}
			}
		}
		if _, derr := p.ReceiveSecureMessage(&em); derr == nil {
			p.p2pRx++
		}
	}
}

func (p *P2PNetwork) startHandshakeListener(ctx context.Context) {
	addr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	if la, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		p.mu.Lock()
		if p.myNode != nil {
			p.myNode.HandshakePort = la.Port
		}
		if p.discovery != nil {
			p.discovery.hsPort = la.Port
		}
		p.mu.Unlock()
	}

	buf := make([]byte, 2048)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					return
				default:
				}
				continue
			}
			continue
		}
		seed, _, _, err := handshake.ServerIKFromFirst(conn, p.ecdhPriv, buf[:n], raddr, nil)
		if err != nil {
			continue
		}
		var peerNodeID string
		p.discovery.mu.RLock()
		for id, nd := range p.discovery.peers {
			if nd != nil && nd.IP == raddr.IP.String() {
				peerNodeID = id
				break
			}
		}
		p.discovery.mu.RUnlock()
		if peerNodeID != "" && p.myNode != nil {
			if s, err := p.encryption.CreateECDHSessionForPeers(p.myNode.ID, peerNodeID, seed); err == nil {
				p.mu.Lock()
				p.sessions[peerNodeID] = s.ID
				p.mu.Unlock()
			}
		}
	}
}
