package tuic

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/logger"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

var log = logger.Module("tuic")

const (
	ModuleName    = "transport.tuic"
	ModuleVersion = "1.0.0"

	tuicALPN = "tuic"
)

type Config struct {
	UUID       string
	Password   string
	ServerAddr string
	SNI        string
	CongestionControl string
}

func DefaultConfig() *Config {
	return &Config{
		CongestionControl: "bbr",
		SNI:               "",
	}
}

func (c *Config) Validate() error {
	if c.ServerAddr == "" {
		return fmt.Errorf("tuic: server address required")
	}
	if c.UUID == "" {
		return fmt.Errorf("tuic: UUID required")
	}
	return nil
}

type Transport struct {
	*base.Module
	config *Config

	conn        *quic.Conn
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

func (t *Transport) Type() interfaces.TransportType { return interfaces.TransportTUIC }

func (t *Transport) Listen(_ string) error     { return fmt.Errorf("tuic: server mode not implemented") }
func (t *Transport) Accept() (net.Conn, error) { return nil, fmt.Errorf("tuic: server mode not implemented") }
func (t *Transport) Close() error {
	if t.conn != nil {
		return t.conn.CloseWithError(0, "close")
	}
	return nil
}

func (t *Transport) getConn(ctx context.Context) (*quic.Conn, error) {
	if t.conn != nil {
		return t.conn, nil
	}

	sni := t.config.SNI
	if sni == "" {
		host, _, _ := net.SplitHostPort(t.config.ServerAddr)
		sni = host
	}

	tlsCfg := &tls.Config{
		ServerName:         sni,
		NextProtos:         []string{tuicALPN},
		InsecureSkipVerify: false,
	}

	conn, err := quic.DialAddr(ctx, t.config.ServerAddr, tlsCfg, &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("tuic: quic dial: %w", err)
	}

	t.conn = conn
	log.Info("tuic: QUIC connection established to %s", t.config.ServerAddr)
	return conn, nil
}

func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	qconn, err := t.getConn(ctx)
	if err != nil {
		return nil, err
	}

	stream, err := qconn.OpenStreamSync(ctx)
	if err != nil {
		t.conn = nil
		return nil, fmt.Errorf("tuic: open stream: %w", err)
	}

	// Send TUIC CONNECT request
	// Format: [UUID(16)] [addr_len(1)] [addr] [port(2)]
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		stream.Close()
		return nil, err
	}

	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	req := make([]byte, 0, 32)
	req = append(req, []byte(t.config.UUID)[:16]...)
	req = append(req, byte(len(host)))
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))

	if _, err := stream.Write(req); err != nil {
		stream.Close()
		return nil, err
	}

	atomic.AddUint64(&t.totalConns, 1)
	atomic.AddInt64(&t.activeConns, 1)

	log.Info("tuic: stream opened to %s", addr)

	return &tuicConn{stream: stream, t: t}, nil
}

func (t *Transport) HealthCheck() interfaces.HealthStatus {
	s := t.Module.HealthCheck()
	s.Details["active_conns"] = atomic.LoadInt64(&t.activeConns)
	s.Details["congestion"] = t.config.CongestionControl
	return s
}

type tuicConn struct {
	stream *quic.Stream
	t      *Transport
}

func (c *tuicConn) Read(b []byte) (int, error) {
	n, err := c.stream.Read(b)
	if n > 0 {
		atomic.AddUint64(&c.t.bytesIn, uint64(n))
	}
	return n, err
}

func (c *tuicConn) Write(b []byte) (int, error) {
	n, err := c.stream.Write(b)
	if n > 0 {
		atomic.AddUint64(&c.t.bytesOut, uint64(n))
	}
	return n, err
}

func (c *tuicConn) Close() error {
	atomic.AddInt64(&c.t.activeConns, -1)
	return c.stream.Close()
}

func (c *tuicConn) LocalAddr() net.Addr               { return &net.UDPAddr{} }
func (c *tuicConn) RemoteAddr() net.Addr              { return &net.UDPAddr{} }
func (c *tuicConn) SetDeadline(t time.Time) error     { return c.stream.SetDeadline(t) }
func (c *tuicConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *tuicConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

var _ io.ReadWriteCloser = (*tuicConn)(nil)

func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
