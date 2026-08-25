package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"

	"time"

	"github.com/nekoskin/whispera/core/protocol"
	"github.com/nekoskin/whispera/core/protocol/fingerprint"
	"github.com/nekoskin/whispera/core/protocol/quic"
	"github.com/nekoskin/whispera/core/transport/grpc"
	"github.com/nekoskin/whispera/core/transport/yadisk"

	quicgo "github.com/quic-go/quic-go"
)

func helloSplitEnabled() bool { return os.Getenv("WHISPERA_HELLO_SPLIT") == "1" }

const altTransportSessionIDLen = 8

func sendAltTransportAuth(conn net.Conn, psk []byte) error {
	if len(psk) != 32 {
		conn.Close()
		return fmt.Errorf("alt transport auth: PSK not available")
	}
	sessionID := make([]byte, altTransportSessionIDLen)
	if _, err := rand.Read(sessionID); err != nil {
		conn.Close()
		return err
	}
	token := protocol.ClientAuthToken(psk, sessionID)
	hdr := make([]byte, 1+altTransportSessionIDLen+2+len(token))
	hdr[0] = byte(altTransportSessionIDLen)
	copy(hdr[1:1+altTransportSessionIDLen], sessionID)
	binary.BigEndian.PutUint16(hdr[1+altTransportSessionIDLen:1+altTransportSessionIDLen+2], uint16(len(token)))
	copy(hdr[1+altTransportSessionIDLen+2:], token)
	if _, err := conn.Write(hdr); err != nil {
		conn.Close()
		return err
	}
	return nil
}

const datagramDialTimeout = 15 * time.Second

type datagramLane struct {
	mu      sync.Mutex
	quicGD  *quic.DatagramClient
	dialing bool
}

type selector struct {
	m *Manager

	sessionCache any
	lane         datagramLane
	strategy     *protocol.HandshakeStrategy
}

func newSelector(m *Manager) *selector {
	strategy := m.config.HandshakeStrategy
	if strategy == nil {
		strategy = protocol.NewHandshakeStrategy()
	}
	return &selector{
		m:            m,
		sessionCache: protocol.SharedSessionCache(),
		strategy:     strategy,
	}
}

func (s *selector) whisperaDial() (func(context.Context) (net.Conn, error), bool) {
	m := s.m
	if !m.config.EnableWhispera || len(m.config.WhisperaSecret) == 0 {
		return nil, false
	}
	addr := m.config.WhisperaAddr
	if addr == "" {
		addr = m.config.ServerAddr
	}
	sni := m.config.WhisperaSNI
	if net.ParseIP(sni) != nil {
		sni = ""
	}
	var tcpDialer func(context.Context, string, string) (net.Conn, error)
	if m.asnBypassDialer != nil {
		tcpDialer = m.asnBypassDialer.DialTCP
	}
	cCfg := &protocol.ClientConfig{
		ServerAddr:    addr,
		ServerName:    sni,
		SharedSecret:  m.config.WhisperaSecret,
		ServerCertPin: m.config.WhisperaCertPin,
		ServerIDPub:   m.config.WhisperaIDPub,
		ServerSelPub:  m.config.WhisperaSelPub,
		SessionCache:  s.sessionCache,
		TCPDialer:     tcpDialer,
	}
	strategy := s.strategy
	splitCtx := sni + "|split"
	return func(ctx context.Context) (net.Conn, error) {
		c := *cCfg
		if c.ServerSelPub == "" {
			c.ServerSelPub = protocol.LearnedSelPub(c.ServerIDPub)
		}
		c.OnServerSelPub = func(selPub string) {
			protocol.RememberSelPub(c.ServerIDPub, selPub)
		}
		arm := strategy.Select(sni, fingerprint.PresetCount())
		c.HelloID = fingerprint.PresetAt(arm)

		splitArm := -1
		if helloSplitEnabled() {
			c.HelloSplitOffset, splitArm = strategy.SelectSplit(splitCtx)
		}

		observe := func(result protocol.HandshakeResult) {
			strategy.Record(sni, result)
			strategy.Observe(sni, arm, result)
			if splitArm >= 0 {
				strategy.Observe(splitCtx, splitArm, result)
			}
		}

		c.OnHandshake = func(result protocol.HandshakeResult, _ time.Duration) {
			if result != protocol.HandshakeOK {
				observe(result)
			}
		}
		c.OnLiveReset = func() { observe(protocol.HandshakeResetFast) }
		c.OnLiveOK = func() { observe(protocol.HandshakeOK) }
		return protocol.Client(ctx, &c)
	}, true
}

func (s *selector) startDatagramLane() {
	m := s.m
	if !m.config.EnableWhispera || m.config.WhisperaQUICAddr == "" || len(m.config.WhisperaSecret) == 0 {
		return
	}

	s.lane.mu.Lock()
	if s.lane.quicGD != nil || s.lane.dialing {
		s.lane.mu.Unlock()
		return
	}
	s.lane.dialing = true
	s.lane.mu.Unlock()

	sni := m.config.WhisperaSNI
	if net.ParseIP(sni) != nil {
		sni = ""
	}
	cfg := &protocol.ClientConfig{
		ServerAddr:    m.config.WhisperaAddr,
		ServerName:    sni,
		SharedSecret:  m.config.WhisperaSecret,
		ServerCertPin: m.config.WhisperaCertPin,
		ServerIDPub:   m.config.WhisperaIDPub,
		ServerSelPub:  m.config.WhisperaSelPub,
		QUICAddr:      m.config.WhisperaQUICAddr,
		OnQUICConn:    s.adoptDatagramConn,
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), datagramDialTimeout)
		defer cancel()

		if err := protocol.DialRTDatagrams(ctx, cfg); err != nil {
			log.Warn("datagram lane unavailable, UDP stays on the tunnel: %v", err)
		}
		s.lane.mu.Lock()
		s.lane.dialing = false
		s.lane.mu.Unlock()
	}()
}

func (s *selector) adoptDatagramConn(c *quicgo.Conn) {
	gd := quic.NewDatagramClient(c)

	s.lane.mu.Lock()
	old := s.lane.quicGD
	s.lane.quicGD = gd
	s.lane.mu.Unlock()
	if old != nil {
		old.Close()
	}

	go func() {
		<-c.Context().Done()
		s.lane.mu.Lock()
		if s.lane.quicGD == gd {
			s.lane.quicGD = nil
		}
		s.lane.mu.Unlock()
		gd.Close()
	}()
}

func (s *selector) grpcDial() (func(context.Context) (net.Conn, error), bool) {
	m := s.m
	if !m.config.EnableGRPC || m.config.GRPCAddr == "" {
		return nil, false
	}
	t, err := grpc.New(&grpc.Config{
		ListenAddr: "127.0.0.1:0",
		ServerName: m.config.GRPCServerName,
		UseTLS:     m.config.GRPCUseTLS,
	})
	if err != nil {
		return nil, false
	}
	addr := m.config.GRPCAddr
	psk := m.config.PSK
	return func(ctx context.Context) (net.Conn, error) {
		conn, err := t.Dial(ctx, addr)
		if err != nil {
			return nil, err
		}
		if err := sendAltTransportAuth(conn, psk); err != nil {
			return nil, err
		}
		return conn, nil
	}, true
}

func (s *selector) yadiskDial() (func(context.Context) (net.Conn, error), bool) {
	m := s.m
	if !m.config.EnableYaDisk || m.config.YaDiskOAuthToken == "" {
		return nil, false
	}
	t, err := yadisk.New(&yadisk.Config{
		OAuthToken: m.config.YaDiskOAuthToken,
		SessionID:  m.config.YaDiskSessionID,
	})
	if err != nil {
		return nil, false
	}
	if err := t.Start(); err != nil {
		return nil, false
	}
	psk := m.config.PSK
	return func(ctx context.Context) (net.Conn, error) {
		conn, err := t.Dial(ctx, "")
		if err != nil {
			return nil, err
		}
		if err := sendAltTransportAuth(conn, psk); err != nil {
			return nil, err
		}
		return conn, nil
	}, true
}

func (s *selector) dial() func(context.Context) (net.Conn, error) {
	if d, ok := s.whisperaDial(); ok {
		return d
	}
	if d, ok := s.grpcDial(); ok {
		return d
	}
	if d, ok := s.yadiskDial(); ok {
		return d
	}
	return nil
}

func (m *Manager) DatagramClient(addr string) (*quic.DatagramClient, bool) {
	if !m.config.EnableWhispera {
		return nil, false
	}
	s := &m.selector.lane
	s.mu.Lock()
	gd := s.quicGD
	s.mu.Unlock()
	return gd, gd != nil
}
