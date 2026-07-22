package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/nekoskin/whispera/core/protocol"
	"github.com/nekoskin/whispera/core/transport/grpc"
	"github.com/nekoskin/whispera/core/transport/yadisk"
	"net"
	"sync"
	"time"

	quicgo "github.com/quic-go/quic-go"
)

const defaultWhisperaSNI = "vk.com"

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

type rtLane struct {
	mu     sync.Mutex
	quicGD *protocol.RTDatagramClient
}

type rtLaneManager struct {
	m *Manager

	sessionCache any
	lane         rtLane
	strategy     *protocol.HandshakeStrategy
}

func newRTLaneManager(m *Manager) *rtLaneManager {
	return &rtLaneManager{
		m:            m,
		sessionCache: protocol.SharedSessionCache(),
		strategy:     protocol.NewHandshakeStrategy(),
	}
}

func (rl *rtLaneManager) whisperaDial() (func(context.Context) (net.Conn, error), bool) {
	m := rl.m
	if !m.config.EnableWhispera || len(m.config.WhisperaSecret) == 0 {
		return nil, false
	}
	addr := m.config.WhisperaAddr
	if addr == "" {
		addr = m.config.ServerAddr
	}
	sni := m.config.WhisperaSNI
	if sni == "" || net.ParseIP(sni) != nil {
		sni = defaultWhisperaSNI
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
		SessionCache:  rl.sessionCache,
		TCPDialer:     tcpDialer,
		EnableQUIC:    m.config.WhisperaQUICAddr != "",
		QUICAddr:      m.config.WhisperaQUICAddr,
		OnQUICConn: func(c *quicgo.Conn) {
			gd := protocol.NewRTDatagramClient(c)
			g := &rl.lane
			g.mu.Lock()
			old := g.quicGD
			g.quicGD = gd
			g.mu.Unlock()
			if old != nil {
				old.Close()
			}
			go func() {
				<-c.Context().Done()
				g.mu.Lock()
				if g.quicGD == gd {
					g.quicGD = nil
				}
				g.mu.Unlock()
				gd.Close()
			}()
		},
	}
	strategy := rl.strategy
	return func(ctx context.Context) (net.Conn, error) {
		offset, arm := strategy.SelectSplit(sni)
		c := *cCfg
		c.HelloSplitOffset = offset
		c.OnHandshake = func(result protocol.HandshakeResult, _ time.Duration) {
			strategy.Observe(sni, arm, result)
		}
		return protocol.Client(ctx, &c)
	}, true
}

func (rl *rtLaneManager) grpcDial() (func(context.Context) (net.Conn, error), bool) {
	m := rl.m
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

func (rl *rtLaneManager) yadiskDial() (func(context.Context) (net.Conn, error), bool) {
	m := rl.m
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

func (rl *rtLaneManager) dial() func(context.Context) (net.Conn, error) {
	if d, ok := rl.whisperaDial(); ok {
		return d
	}
	if d, ok := rl.grpcDial(); ok {
		return d
	}
	if d, ok := rl.yadiskDial(); ok {
		return d
	}
	return nil
}

func (m *Manager) RTDatagram(ctx context.Context, addr string) (*protocol.RTDatagramClient, func(), bool) {
	if !m.config.EnableWhispera {
		return nil, nil, false
	}
	gd, ok := m.rtLane.AcquireRTDatagram(ctx)
	if !ok {
		return nil, nil, false
	}
	return gd, m.rtLane.ReleaseRTDatagram, true
}

func (rl *rtLaneManager) AcquireRTDatagram(ctx context.Context) (gd *protocol.RTDatagramClient, ok bool) {
	g := &rl.lane
	g.mu.Lock()
	gd = g.quicGD
	g.mu.Unlock()
	return gd, gd != nil
}

func (rl *rtLaneManager) ReleaseRTDatagram() {}
