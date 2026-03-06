package splithttp

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

var log = logger.Module("splithttp")

const (
	ModuleName    = "transport.splithttp"
	ModuleVersion = "1.0.0"

	maxChunkSize = 1 << 17 // 128KB
)

// SplitHTTP (XHTTP) sends data via POST and receives via chunked GET.
// This makes it hard for DPI to distinguish from regular HTTP traffic.
type Config struct {
	BaseURL string
	Host    string
	Path    string
}

func DefaultConfig() *Config {
	return &Config{
		Path: "/",
	}
}

func (c *Config) Validate() error {
	if c.BaseURL == "" {
		return fmt.Errorf("splithttp: base URL required")
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
				MaxIdleConns:    10,
				IdleConnTimeout: 90 * time.Second,
			},
		},
	}, nil
}

func (t *Transport) Type() interfaces.TransportType { return interfaces.TransportSplitHTTP }

func (t *Transport) Listen(_ string) error     { return fmt.Errorf("splithttp: server mode not implemented") }
func (t *Transport) Accept() (net.Conn, error) { return nil, fmt.Errorf("splithttp: server mode not implemented") }
func (t *Transport) Close() error              { return nil }

func (t *Transport) Dial(ctx context.Context, _ string) (net.Conn, error) {
	b := make([]byte, 16)
	rand.Read(b)
	sessionID := hex.EncodeToString(b)

	pr, pw := io.Pipe()
	conn := &splitHTTPConn{
		t:         t,
		sessionID: sessionID,
		recvPipe:  pr,
		sendCh:    make(chan []byte, 64),
		done:      make(chan struct{}),
	}

	// Start GET stream for receiving data
	go conn.startRecvStream(ctx)
	// Start POST loop for sending data
	go conn.sendLoop(ctx, pw)

	atomic.AddUint64(&t.totalConns, 1)
	atomic.AddInt64(&t.activeConns, 1)

	log.Info("splithttp: connection established, session=%s", sessionID)
	return conn, nil
}

func (t *Transport) HealthCheck() interfaces.HealthStatus {
	s := t.Module.HealthCheck()
	s.Details["active_conns"] = atomic.LoadInt64(&t.activeConns)
	return s
}

type splitHTTPConn struct {
	t         *Transport
	sessionID string

	mu       sync.Mutex
	pending  []byte
	recvPipe *io.PipeReader
	sendCh   chan []byte
	done     chan struct{}
	once     sync.Once
}

func (c *splitHTTPConn) startRecvStream(ctx context.Context) {
	url := c.t.config.BaseURL + "?session=" + c.sessionID

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return
	}
	if c.t.config.Host != "" {
		req.Host = c.t.config.Host
	}

	resp, err := c.t.client.Do(req)
	if err != nil {
		c.closeOnce()
		return
	}
	defer resp.Body.Close()

	buf := make([]byte, 32*1024)
	for {
		select {
		case <-c.done:
			return
		default:
		}
		n, err := resp.Body.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			c.mu.Lock()
			c.pending = append(c.pending, data...)
			c.mu.Unlock()
			atomic.AddUint64(&c.t.bytesIn, uint64(n))
		}
		if err != nil {
			c.closeOnce()
			return
		}
	}
}

func (c *splitHTTPConn) sendLoop(ctx context.Context, pw *io.PipeWriter) {
	defer pw.Close()
	for {
		select {
		case <-c.done:
			return
		case data := <-c.sendCh:
			url := c.t.config.BaseURL + "?session=" + c.sessionID
			req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
			if err != nil {
				continue
			}
			if c.t.config.Host != "" {
				req.Host = c.t.config.Host
			}
			req.Header.Set("Content-Type", "application/octet-stream")
			resp, err := c.t.client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()
			atomic.AddUint64(&c.t.bytesOut, uint64(len(data)))
		}
	}
}

func (c *splitHTTPConn) Read(b []byte) (int, error) {
	for {
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
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (c *splitHTTPConn) Write(b []byte) (int, error) {
	select {
	case <-c.done:
		return 0, io.ErrClosedPipe
	case c.sendCh <- append([]byte(nil), b...):
		return len(b), nil
	}
}

func (c *splitHTTPConn) closeOnce() {
	c.once.Do(func() {
		close(c.done)
		atomic.AddInt64(&c.t.activeConns, -1)
	})
}

func (c *splitHTTPConn) Close() error {
	c.closeOnce()
	return nil
}

func (c *splitHTTPConn) LocalAddr() net.Addr               { return &net.TCPAddr{} }
func (c *splitHTTPConn) RemoteAddr() net.Addr              { return &net.TCPAddr{} }
func (c *splitHTTPConn) SetDeadline(_ time.Time) error     { return nil }
func (c *splitHTTPConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *splitHTTPConn) SetWriteDeadline(_ time.Time) error { return nil }

func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
