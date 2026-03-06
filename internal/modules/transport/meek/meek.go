package meek

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
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

var log = logger.Module("meek")

const (
	ModuleName   = "transport.meek"
	ModuleVersion = "1.0.0"

	pollInterval = 100 * time.Millisecond
	maxPayload   = 0x10000
)

type Config struct {
	URL         string
	FrontDomain string
}

func DefaultConfig() *Config {
	return &Config{
		URL:         "https://meek.azureedge.net/",
		FrontDomain: "ajax.aspnetcdn.com",
	}
}

func (c *Config) Validate() error {
	if c.URL == "" {
		return fmt.Errorf("meek URL is required")
	}
	return nil
}

type Transport struct {
	*base.Module
	config *Config
	client *http.Client

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
		client: &http.Client{
			Transport: &http.Transport{
				TLSHandshakeTimeout: 10 * time.Second,
				MaxIdleConns:        10,
			},
		},
	}, nil
}

func (t *Transport) Type() interfaces.TransportType { return interfaces.TransportMeek }

func (t *Transport) Listen(_ string) error           { return fmt.Errorf("meek: server mode not supported") }
func (t *Transport) Accept() (net.Conn, error)       { return nil, fmt.Errorf("meek: server mode not supported") }
func (t *Transport) Close() error                    { return nil }

func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	b := make([]byte, 8)
	rand.Read(b)
	sessionID := hex.EncodeToString(b)

	conn := &meekConn{
		t:         t,
		sessionID: sessionID,
		recvCh:    make(chan []byte, 64),
		sendCh:    make(chan []byte, 64),
		done:      make(chan struct{}),
	}

	atomic.AddUint64(&t.totalConns, 1)
	atomic.AddInt64(&t.activeConns, 1)

	go conn.loop(ctx)
	return conn, nil
}

func (t *Transport) HealthCheck() interfaces.HealthStatus {
	s := t.Module.HealthCheck()
	s.Details["active_conns"] = atomic.LoadInt64(&t.activeConns)
	return s
}

type meekConn struct {
	t         *Transport
	sessionID string

	mu      sync.Mutex
	pending []byte

	recvCh chan []byte
	sendCh chan []byte
	done   chan struct{}
	once   sync.Once
}

func (c *meekConn) loop(ctx context.Context) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			c.closeOnce()
			return
		case <-c.done:
			return
		case data := <-c.sendCh:
			c.roundTrip(ctx, data)
		case <-ticker.C:
			c.roundTrip(ctx, nil)
		}
	}
}

func (c *meekConn) roundTrip(ctx context.Context, body []byte) {
	if body == nil {
		body = []byte{}
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.t.config.URL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Host = c.t.config.FrontDomain
	req.Header.Set("X-Session-Id", c.sessionID)
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := c.t.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxPayload))
	if err != nil || len(data) == 0 {
		return
	}
	atomic.AddUint64(&c.t.bytesIn, uint64(len(data)))
	select {
	case c.recvCh <- data:
	default:
	}
}

func (c *meekConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	if len(c.pending) > 0 {
		n := copy(b, c.pending)
		c.pending = c.pending[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()

	select {
	case <-c.done:
		return 0, io.EOF
	case data := <-c.recvCh:
		n := copy(b, data)
		if n < len(data) {
			c.mu.Lock()
			c.pending = append(c.pending, data[n:]...)
			c.mu.Unlock()
		}
		return n, nil
	}
}

func (c *meekConn) Write(b []byte) (int, error) {
	select {
	case <-c.done:
		return 0, io.ErrClosedPipe
	case c.sendCh <- append([]byte(nil), b...):
		atomic.AddUint64(&c.t.bytesOut, uint64(len(b)))
		return len(b), nil
	}
}

func (c *meekConn) closeOnce() {
	c.once.Do(func() {
		close(c.done)
		atomic.AddInt64(&c.t.activeConns, -1)
	})
}

func (c *meekConn) Close() error {
	c.closeOnce()
	return nil
}

func (c *meekConn) LocalAddr() net.Addr               { return &net.TCPAddr{} }
func (c *meekConn) RemoteAddr() net.Addr              { return &net.TCPAddr{} }
func (c *meekConn) SetDeadline(_ time.Time) error     { return nil }
func (c *meekConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *meekConn) SetWriteDeadline(_ time.Time) error { return nil }

func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
