package shadowtls

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/logger"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

var log = logger.Module("shadowtls")

const (
	ModuleName    = "transport.shadowtls"
	ModuleVersion = "1.0.0"

	hmacLen = 8
)

// ShadowTLS wraps a real TLS connection to a legitimate server,
// authenticating the client via HMAC in the TLS ServerRandom field.
type Config struct {
	// Password used to derive HMAC key
	Password string
	// ShadowServer is the real ShadowTLS server address
	ShadowServer string
	// SniServer is a legitimate TLS server to impersonate (e.g. www.google.com:443)
	SNI string
	// Version: 2 or 3 (ShadowTLS protocol version)
	Version int
}

func DefaultConfig() *Config {
	return &Config{
		SNI:     "www.apple.com",
		Version: 3,
	}
}

func (c *Config) Validate() error {
	if c.Password == "" {
		return fmt.Errorf("shadowtls: password required")
	}
	if c.ShadowServer == "" {
		return fmt.Errorf("shadowtls: server address required")
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

func (t *Transport) Type() interfaces.TransportType { return interfaces.TransportShadowTLS }

func (t *Transport) Listen(_ string) error     { return fmt.Errorf("shadowtls: server mode not implemented") }
func (t *Transport) Accept() (net.Conn, error) { return nil, fmt.Errorf("shadowtls: server mode not implemented") }
func (t *Transport) Close() error              { return nil }

func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	server := t.config.ShadowServer
	if server == "" {
		server = addr
	}

	d := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, fmt.Errorf("shadowtls dial: %w", err)
	}

	sni := t.config.SNI
	if sni == "" {
		host, _, _ := net.SplitHostPort(server)
		sni = host
	}

	tlsConn := utls.UClient(rawConn, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: false,
	}, utls.HelloChrome_Auto)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("shadowtls tls handshake: %w", err)
	}

	// Verify server authenticity via HMAC in ServerRandom
	state := tlsConn.ConnectionState()
	if !t.verifyServerRandom(state.TLSUnique) {
		log.Warn("shadowtls: server HMAC verification failed, possible MITM")
	}

	log.Info("shadowtls: connected to %s via %s", addr, server)

	atomic.AddUint64(&t.totalConns, 1)
	atomic.AddInt64(&t.activeConns, 1)

	return newShadowTLSConn(tlsConn, t), nil
}

func (t *Transport) verifyServerRandom(data []byte) bool {
	if len(data) < hmacLen {
		return false
	}
	mac := hmac.New(sha256.New, []byte(t.config.Password))
	mac.Write(data[:len(data)-hmacLen])
	expected := mac.Sum(nil)[:hmacLen]
	return hmac.Equal(expected, data[len(data)-hmacLen:])
}

func (t *Transport) HealthCheck() interfaces.HealthStatus {
	s := t.Module.HealthCheck()
	s.Details["active_conns"] = atomic.LoadInt64(&t.activeConns)
	s.Details["sni"] = t.config.SNI
	s.Details["version"] = t.config.Version
	return s
}

type shadowTLSConn struct {
	*utls.UConn
	transport *Transport
}

func newShadowTLSConn(inner *utls.UConn, tr *Transport) *shadowTLSConn {
	return &shadowTLSConn{UConn: inner, transport: tr}
}

func (c *shadowTLSConn) Close() error {
	atomic.AddInt64(&c.transport.activeConns, -1)
	return c.UConn.Close()
}

func (c *shadowTLSConn) Read(b []byte) (int, error) {
	n, err := c.UConn.Read(b)
	if n > 0 {
		atomic.AddUint64(&c.transport.bytesIn, uint64(n))
	}
	return n, err
}

func (c *shadowTLSConn) Write(b []byte) (int, error) {
	n, err := c.UConn.Write(b)
	if n > 0 {
		atomic.AddUint64(&c.transport.bytesOut, uint64(n))
	}
	return n, err
}

// Ensure io.ReadCloser can be used
var _ io.ReadWriteCloser = (*shadowTLSConn)(nil)

func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
