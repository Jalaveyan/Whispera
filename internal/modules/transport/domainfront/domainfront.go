package domainfront

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/logger"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

var log = logger.Module("domainfront")

const (
	ModuleName    = "transport.domainfront"
	ModuleVersion = "1.0.0"
)

type Config struct {
	FrontDomain  string
	TargetDomain string
	Path         string
	// Mode controls how the tunnel is established through the CDN.
	//   "connect"   — HTTP CONNECT (works with HTTPS forward proxies)
	//   "websocket" — WebSocket Upgrade with Host: TargetDomain (works with CDNs
	//                 like Cloudflare that proxy WebSocket by Host header)
	// Default: "websocket" (works with modern CDNs).
	Mode string
	// WSPath is the WebSocket endpoint path when Mode="websocket".
	WSPath string
}

func DefaultConfig() *Config {
	return &Config{
		Path:   "/",
		Mode:   "websocket",
		WSPath: "/ws",
	}
}

func (c *Config) Validate() error {
	if c.FrontDomain == "" {
		return fmt.Errorf("domainfront: front domain required")
	}
	if c.TargetDomain == "" {
		return fmt.Errorf("domainfront: target domain required")
	}
	if c.Mode == "" {
		c.Mode = "websocket"
	}
	return nil
}

type Transport struct {
	*base.Module
	config *Config

	activeConns int64
	totalConns  uint64
	bytesIn     uint64
	bytesOut    uint64
}

func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Transport{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: cfg,
	}, nil
}

func (t *Transport) Type() interfaces.TransportType { return interfaces.TransportDomainFront }

func (t *Transport) Listen(_ string) error     { return fmt.Errorf("domainfront: server mode not supported") }
func (t *Transport) Accept() (net.Conn, error) { return nil, fmt.Errorf("domainfront: server mode not supported") }
func (t *Transport) Close() error              { return nil }

func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	switch t.config.Mode {
	case "websocket":
		return t.dialWebSocket(ctx)
	default:
		return t.dialConnect(ctx, addr)
	}
}

// dialConnect uses HTTP CONNECT tunneling — works with HTTPS forward proxies.
func (t *Transport) dialConnect(ctx context.Context, addr string) (net.Conn, error) {
	tlsConn, err := t.tlsDial(ctx)
	if err != nil {
		return nil, err
	}

	req := fmt.Sprintf(
		"CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
		addr, t.config.TargetDomain,
	)
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		tlsConn.Close()
		return nil, err
	}

	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("domainfront: read CONNECT response: %w", err)
	}
	resp.Body.Close()
	tlsConn.SetDeadline(time.Time{})

	if resp.StatusCode != http.StatusOK {
		tlsConn.Close()
		return nil, fmt.Errorf("domainfront: CONNECT failed, status=%d", resp.StatusCode)
	}

	atomic.AddUint64(&t.totalConns, 1)
	atomic.AddInt64(&t.activeConns, 1)
	log.Info("domainfront: CONNECT %s via %s → %s", addr, t.config.FrontDomain, t.config.TargetDomain)
	return &frontConn{Conn: tlsConn, t: t}, nil
}

// dialWebSocket uses a WebSocket Upgrade request with Host: TargetDomain.
// This is the standard CDN domain-fronting technique:
//   - TLS SNI = FrontDomain  (visible to DPI — looks like traffic to FrontDomain)
//   - HTTP Host = TargetDomain (CDN routes by Host to origin)
//
// Works with Cloudflare, Fastly, CloudFront in WebSocket proxy mode.
func (t *Transport) dialWebSocket(ctx context.Context) (net.Conn, error) {
	tlsConn, err := t.tlsDial(ctx)
	if err != nil {
		return nil, err
	}

	wsPath := t.config.WSPath
	if wsPath == "" {
		wsPath = "/ws"
	}

	// Random WebSocket key (RFC 6455).
	key := make([]byte, 16)
	rand.Read(key)
	wsKey := base64.StdEncoding.EncodeToString(key)

	req := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"User-Agent: Mozilla/5.0\r\n"+
			"\r\n",
		wsPath, t.config.TargetDomain, wsKey,
	)

	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("domainfront ws: write upgrade: %w", err)
	}

	br := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("domainfront ws: read upgrade response: %w", err)
	}
	resp.Body.Close()
	tlsConn.SetDeadline(time.Time{})

	if resp.StatusCode != http.StatusSwitchingProtocols {
		tlsConn.Close()
		return nil, fmt.Errorf("domainfront ws: upgrade failed, status=%d", resp.StatusCode)
	}

	atomic.AddUint64(&t.totalConns, 1)
	atomic.AddInt64(&t.activeConns, 1)
	log.Info("domainfront: WebSocket %s → %s (SNI=%s)", wsPath, t.config.TargetDomain, t.config.FrontDomain)
	return &frontConn{Conn: tlsConn, t: t}, nil
}

// tlsDial opens a TLS connection to FrontDomain with FrontDomain as SNI.
func (t *Transport) tlsDial(ctx context.Context) (*tls.Conn, error) {
	frontAddr := net.JoinHostPort(t.config.FrontDomain, "443")
	d := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := d.DialContext(ctx, "tcp", frontAddr)
	if err != nil {
		return nil, fmt.Errorf("domainfront: dial %s: %w", frontAddr, err)
	}
	tlsConn := tls.Client(rawConn, &tls.Config{ServerName: t.config.FrontDomain})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("domainfront: tls handshake: %w", err)
	}
	return tlsConn, nil
}

func (t *Transport) HealthCheck() interfaces.HealthStatus {
	s := t.Module.HealthCheck()
	s.Details["front_domain"] = t.config.FrontDomain
	s.Details["target_domain"] = t.config.TargetDomain
	s.Details["active_conns"] = atomic.LoadInt64(&t.activeConns)
	return s
}

type frontConn struct {
	net.Conn
	t *Transport
}

func (c *frontConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		atomic.AddUint64(&c.t.bytesIn, uint64(n))
	}
	return n, err
}

func (c *frontConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		atomic.AddUint64(&c.t.bytesOut, uint64(n))
	}
	return n, err
}

func (c *frontConn) Close() error {
	atomic.AddInt64(&c.t.activeConns, -1)
	return c.Conn.Close()
}

func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
