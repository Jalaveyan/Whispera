package shadowtls

// ShadowTLS v3 transport.
//
// How it works:
//   Client → Server: raw TCP
//   Server proxies the full TLS handshake to a real "shadow" host (e.g. www.apple.com).
//   DPI sees a legitimate TLS 1.3 session to Apple — because it IS one.
//   After the handshake the client injects an 8-byte HMAC token into its first
//   ApplicationData record. The server checks the token:
//     valid  → strip the 8 bytes, hand the conn to the tunnel layer.
//     invalid → stay in passthrough mode, forever proxying to the shadow host.
//
// HMAC token = HMAC-SHA256(password, floor(unix_time/60))[:8]
// Server accepts tokens for the current and previous 60-second window (clock skew).

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
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
	ModuleVersion = "2.0.0"

	tokenLen       = 8
	maxCheckRecord = 5  // give up auth check after this many type-23 records
	proxyTimeout   = 30 * time.Second
)

// --------------------------------------------------------------------------
// Config
// --------------------------------------------------------------------------

type Config struct {
	Password string

	// ShadowServer is the address the server proxies the TLS handshake to.
	// Example: "www.apple.com:443"
	ShadowServer string

	// SNI sent in the ClientHello (should match ShadowServer).
	SNI string

	// ServerMode: true on the Whispera server side.
	ServerMode bool

	// Version is kept for config compatibility; only v3 logic is implemented.
	Version int
}

func DefaultConfig() *Config {
	return &Config{
		SNI:          "www.apple.com",
		ShadowServer: "www.apple.com:443",
		Version:      3,
	}
}

func (c *Config) Validate() error {
	if c.Password == "" {
		return fmt.Errorf("shadowtls: password required")
	}
	if c.ServerMode && c.ShadowServer == "" {
		return fmt.Errorf("shadowtls: shadow_server required in server mode")
	}
	if !c.ServerMode && c.ShadowServer == "" {
		return fmt.Errorf("shadowtls: server address required for client mode")
	}
	return nil
}

// --------------------------------------------------------------------------
// Transport
// --------------------------------------------------------------------------

type Transport struct {
	*base.Module
	config   *Config
	listener net.Listener

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

// --------------------------------------------------------------------------
// Server side
// --------------------------------------------------------------------------

func (t *Transport) Listen(addr string) error {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		return fmt.Errorf("shadowtls: listen %s: %w", addr, err)
	}
	t.listener = ln
	log.Info("shadowtls v3: raw listener on %s, shadow=%s", addr, t.config.ShadowServer)
	return nil
}

func (t *Transport) Accept() (net.Conn, error) {
	if t.listener == nil {
		return nil, fmt.Errorf("shadowtls: not listening")
	}
	for {
		raw, err := t.listener.Accept()
		if err != nil {
			return nil, err
		}
		atomic.AddUint64(&t.totalConns, 1)
		atomic.AddInt64(&t.activeConns, 1)
		go func(c net.Conn) {
			// shadowAccept either returns a tunnel conn or handles passthrough internally.
			// We can't block Accept() so we use a channel.
			// (In practice the tunnel layer calls Accept() sequentially.)
		}(raw)
		// Block until this connection is resolved.
		tunnelConn, err := t.shadowAccept(raw)
		if err != nil {
			// passthrough completed or error — try next connection
			atomic.AddInt64(&t.activeConns, -1)
			continue
		}
		return tunnelConn, nil
	}
}

// shadowAccept proxies the TLS handshake to the shadow server, then checks
// for the HMAC auth token in the first client ApplicationData records.
// Returns the authenticated net.Conn on success, error (+ handles passthrough) otherwise.
func (t *Transport) shadowAccept(clientConn net.Conn) (net.Conn, error) {
	defer func() {
		if r := recover(); r != nil {
			log.Warn("shadowtls: panic in shadowAccept: %v", r)
		}
	}()

	shadowConn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(context.Background(), "tcp", t.config.ShadowServer)
	if err != nil {
		clientConn.Close()
		return nil, fmt.Errorf("shadowtls: dial shadow %s: %w", t.config.ShadowServer, err)
	}

	// Proxy TLS handshake bidirectionally, tracking client AppData records.
	authConn, err := t.proxyHandshakeAndAuth(clientConn, shadowConn)
	if err != nil {
		// passthrough ran to completion (connection closed by one side)
		clientConn.Close()
		shadowConn.Close()
		return nil, err
	}
	shadowConn.Close()
	return authConn, nil
}

// proxyHandshakeAndAuth reads TLS records from both sides.
// Once it detects the HMAC token in a client AppData record it returns
// a net.Conn representing the authenticated channel. If no valid token
// arrives within maxCheckRecord client AppData records it enters permanent
// passthrough mode and returns an error when the connection closes.
func (t *Transport) proxyHandshakeAndAuth(client, shadow net.Conn) (net.Conn, error) {
	type authResult struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan authResult, 1)

	// shadow→client pipe (runs in background always)
	go func() {
		io.Copy(client, shadow)
	}()

	clientAppDataSeen := 0
	var pending []byte // leftover bytes from the auth record after stripping token

	for {
		client.SetReadDeadline(time.Now().Add(proxyTimeout))
		ct, data, err := readTLSRecord(client)
		if err != nil {
			return nil, fmt.Errorf("read from client: %w", err)
		}
		client.SetReadDeadline(time.Time{})

		if ct != 23 { // not ApplicationData — proxy to shadow
			if err := writeTLSRecord(shadow, ct, data); err != nil {
				return nil, fmt.Errorf("write to shadow: %w", err)
			}
			continue
		}

		// ApplicationData record from client
		clientAppDataSeen++
		if clientAppDataSeen <= maxCheckRecord {
			// Check for auth token
			if len(data) >= tokenLen && t.checkToken(data[:tokenLen]) {
				// Auth success — remaining bytes after token go to tunnel
				if len(data) > tokenLen {
					pending = data[tokenLen:]
				}
				log.Info("shadowtls: client authenticated (appdata #%d)", clientAppDataSeen)
				_ = resultCh // keep vet happy
				return &serverTunnelConn{
					Conn:    client,
					pending: pending,
					onClose: func() { atomic.AddInt64(&t.activeConns, -1) },
				}, nil
			}
		}

		// No valid token — forward this record to shadow (passthrough)
		if err := writeTLSRecord(shadow, ct, data); err != nil {
			return nil, fmt.Errorf("passthrough write: %w", err)
		}

		if clientAppDataSeen > maxCheckRecord {
			// Give up auth checking — full passthrough until connection closes
			log.Info("shadowtls: no auth token, entering passthrough mode")
			io.Copy(shadow, client) // client→shadow
			return nil, fmt.Errorf("passthrough complete")
		}
	}
}

// --------------------------------------------------------------------------
// Client side
// --------------------------------------------------------------------------

func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	server := t.config.ShadowServer
	if server == "" {
		server = addr
	}
	sni := t.config.SNI
	if sni == "" {
		host, _, _ := net.SplitHostPort(server)
		sni = host
	}

	d := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, fmt.Errorf("shadowtls dial: %w", err)
	}

	tlsConn := utls.UClient(rawConn, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // shadow cert won't match our server
	}, utls.HelloChrome_Auto)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("shadowtls handshake: %w", err)
	}

	log.Info("shadowtls: connected to %s (SNI=%s)", server, sni)
	atomic.AddUint64(&t.totalConns, 1)
	atomic.AddInt64(&t.activeConns, 1)

	return &clientTunnelConn{
		UConn:     tlsConn,
		token:     t.makeToken(),
		transport: t,
	}, nil
}

func (t *Transport) DialConn(ctx context.Context, conn net.Conn, _ string) (net.Conn, error) {
	sni := t.config.SNI
	if sni == "" {
		sni = "www.apple.com"
	}
	tlsConn := utls.UClient(conn, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	}, utls.HelloChrome_Auto)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("shadowtls DialConn: %w", err)
	}
	atomic.AddUint64(&t.totalConns, 1)
	atomic.AddInt64(&t.activeConns, 1)
	return &clientTunnelConn{
		UConn:     tlsConn,
		token:     t.makeToken(),
		transport: t,
	}, nil
}

// --------------------------------------------------------------------------
// HMAC token (TOTP-style, 60-second window)
// --------------------------------------------------------------------------

func makeToken(password string, window int64) []byte {
	mac := hmac.New(sha256.New, []byte(password))
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(window))
	mac.Write(buf[:])
	return mac.Sum(nil)[:tokenLen]
}

func (t *Transport) makeToken() []byte {
	return makeToken(t.config.Password, time.Now().Unix()/60)
}

func (t *Transport) checkToken(b []byte) bool {
	now := time.Now().Unix() / 60
	for _, w := range []int64{now, now - 1} {
		if hmac.Equal(b, makeToken(t.config.Password, w)) {
			return true
		}
	}
	return false
}

// --------------------------------------------------------------------------
// TLS record layer helpers
// --------------------------------------------------------------------------

func readTLSRecord(r io.Reader) (contentType byte, data []byte, err error) {
	hdr := make([]byte, 5)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return 0, nil, err
	}
	length := int(binary.BigEndian.Uint16(hdr[3:5]))
	if length > 1<<14+256 {
		return 0, nil, fmt.Errorf("record too large: %d", length)
	}
	data = make([]byte, length)
	if _, err = io.ReadFull(r, data); err != nil {
		return 0, nil, err
	}
	return hdr[0], data, nil
}

func writeTLSRecord(w io.Writer, contentType byte, data []byte) error {
	hdr := []byte{
		contentType,
		0x03, 0x03, // TLS 1.2 version field (standard)
		byte(len(data) >> 8),
		byte(len(data)),
	}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// --------------------------------------------------------------------------
// Conn wrappers
// --------------------------------------------------------------------------

// serverTunnelConn is returned by Accept() after auth succeeds.
type serverTunnelConn struct {
	net.Conn
	mu      sync.Mutex
	pending []byte // bytes after stripped token
	onClose func()
}

func (c *serverTunnelConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	if len(c.pending) > 0 {
		n := copy(b, c.pending)
		c.pending = c.pending[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()
	return c.Conn.Read(b)
}

func (c *serverTunnelConn) Close() error {
	if c.onClose != nil {
		c.onClose()
		c.onClose = nil
	}
	return c.Conn.Close()
}

// clientTunnelConn injects the auth token in the very first Write.
type clientTunnelConn struct {
	*utls.UConn
	mu        sync.Mutex
	token     []byte
	injected  bool
	transport *Transport
}

func (c *clientTunnelConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if !c.injected {
		c.injected = true
		payload := make([]byte, tokenLen+len(b))
		copy(payload, c.token)
		copy(payload[tokenLen:], b)
		c.mu.Unlock()
		if _, err := c.UConn.Write(payload); err != nil {
			return 0, err
		}
		atomic.AddUint64(&c.transport.bytesOut, uint64(len(b)))
		return len(b), nil
	}
	c.mu.Unlock()
	n, err := c.UConn.Write(b)
	atomic.AddUint64(&c.transport.bytesOut, uint64(n))
	return n, err
}

func (c *clientTunnelConn) Read(b []byte) (int, error) {
	n, err := c.UConn.Read(b)
	atomic.AddUint64(&c.transport.bytesIn, uint64(n))
	return n, err
}

func (c *clientTunnelConn) Close() error {
	atomic.AddInt64(&c.transport.activeConns, -1)
	return c.UConn.Close()
}

// --------------------------------------------------------------------------
// Misc
// --------------------------------------------------------------------------

func (t *Transport) HealthCheck() interfaces.HealthStatus {
	s := t.Module.HealthCheck()
	s.Details["active_conns"] = atomic.LoadInt64(&t.activeConns)
	s.Details["sni"] = t.config.SNI
	s.Details["shadow_server"] = t.config.ShadowServer
	s.Details["version"] = 3
	return s
}

func (t *Transport) Close() error {
	if t.listener != nil {
		return t.listener.Close()
	}
	return nil
}

func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return &Transport{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: config,
	}, nil
}
