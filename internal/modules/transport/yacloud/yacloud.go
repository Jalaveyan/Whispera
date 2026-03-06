package yacloud

// yacloud — WebSocket tunnel through Yandex Cloud API Gateway.
//
// Traffic is encapsulated as binary WebSocket frames over a connection to
// apigw.yandexcloud.net.  From the firewall's perspective the traffic looks
// like a normal HTTPS/WSS request to Yandex Cloud, which is always in the
// Russian IP CIDR whitelist.
//
// # Deployment
//
// Server side (outside Russia):
//  1. Deploy a Yandex Cloud API Gateway with a WebSocket integration:
//     https://cloud.yandex.ru/docs/api-gateway/concepts/extensions/websocket
//  2. Point the integration to your VPN server's WebSocket listener
//     (e.g. ws://YOUR_VPN_SERVER:8443/ws).
//  3. Set Config.GatewayURL to wss://<gateway-id>.apigw.yandexcloud.net/ws
//
// Client side (in Russia):
//  1. Set Config.GatewayURL to the same URL.
//  2. Call Dial() — the transport connects to Yandex Cloud and the gateway
//     transparently proxies the connection to your VPN server.
//
// No WebRTC or TURN is needed — the tunnel is a plain binary WebSocket.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"nhooyr.io/websocket"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/logger"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

var log = logger.Module("yacloud")

const (
	ModuleName    = "transport.yacloud"
	ModuleVersion = "1.0.0"
)

// Config holds the Yandex Cloud WebSocket transport configuration.
type Config struct {
	// GatewayURL is the full wss:// URL of the Yandex API Gateway endpoint.
	// Example: wss://abcdef123456.apigw.yandexcloud.net/ws
	GatewayURL string

	// ServerMode: if true, Listen() accepts incoming proxied WS connections.
	// In server mode GatewayURL is ignored; use ListenAddr instead.
	ServerMode bool
	ListenAddr string

	// Headers added to the WebSocket upgrade request (for authentication
	// or to mimic a Yandex web app).
	ExtraHeaders map[string]string

	BufferSize int
}

func DefaultConfig() *Config {
	return &Config{
		BufferSize: 32 * 1024,
		ListenAddr: ":8443",
	}
}

// Transport is the Yandex Cloud WebSocket VPN transport.
type Transport struct {
	*base.Module
	config *Config
	srv    *http.Server

	connCh   chan net.Conn
	stopOnce sync.Once
	stopCh   chan struct{}
}

func Factory(cfg interface{}) (interfaces.Module, error) {
	c, ok := cfg.(*Config)
	if !ok {
		c = DefaultConfig()
	}
	return New(c)
}

func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if cfg.BufferSize == 0 {
		cfg.BufferSize = 32 * 1024
	}
	t := &Transport{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: cfg,
		connCh: make(chan net.Conn, 8),
		stopCh: make(chan struct{}),
	}
	return t, nil
}

func (t *Transport) Start() error {
	if t.config.ServerMode {
		mux := http.NewServeMux()
		mux.HandleFunc("/ws", t.wsHandler)
		t.srv = &http.Server{Addr: t.config.ListenAddr, Handler: mux}
		go func() {
			log.Printf("yacloud server listening on %s", t.config.ListenAddr)
			if err := t.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("server error: %v", err)
			}
		}()
	}
	return nil
}

func (t *Transport) Stop() error {
	t.stopOnce.Do(func() {
		close(t.stopCh)
		if t.srv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			t.srv.Shutdown(ctx)
		}
	})
	return nil
}

// Dial connects to the Yandex API Gateway WebSocket and returns a net.Conn.
// The addr parameter is ignored — the gateway URL is taken from Config.
func (t *Transport) Dial(ctx context.Context, _ string) (net.Conn, error) {
	if t.config.GatewayURL == "" {
		return nil, fmt.Errorf("yacloud: GatewayURL is not set")
	}

	opts := &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Origin":     []string{"https://console.cloud.yandex.ru"},
			"User-Agent": []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
		},
	}
	for k, v := range t.config.ExtraHeaders {
		opts.HTTPHeader.Set(k, v)
	}

	ws, _, err := websocket.Dial(ctx, t.config.GatewayURL, opts)
	if err != nil {
		return nil, fmt.Errorf("yacloud dial %s: %w", t.config.GatewayURL, err)
	}
	ws.SetReadLimit(int64(t.config.BufferSize) * 4)

	log.Printf("yacloud: connected to %s", t.config.GatewayURL)
	return newWSConn(ws, t.config.GatewayURL), nil
}

// Accept returns the next client connection (server mode only).
func (t *Transport) Accept() (net.Conn, error) {
	select {
	case conn := <-t.connCh:
		return conn, nil
	case <-t.stopCh:
		return nil, fmt.Errorf("yacloud: stopped")
	}
}

// wsHandler is the HTTP handler for incoming WebSocket connections (server mode).
func (t *Transport) wsHandler(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Printf("yacloud: ws accept error: %v", err)
		return
	}
	ws.SetReadLimit(int64(t.config.BufferSize) * 4)
	conn := newWSConn(ws, r.RemoteAddr)
	select {
	case t.connCh <- conn:
	case <-t.stopCh:
		ws.Close(websocket.StatusGoingAway, "stopped")
	}
}

// wsConn wraps nhooyr.io/websocket as a net.Conn using binary messages.
type wsConn struct {
	ws       *websocket.Conn
	addr     string
	buf      []byte
	bufStart int
	mu       sync.Mutex
}

func newWSConn(ws *websocket.Conn, addr string) *wsConn {
	return &wsConn{ws: ws, addr: addr}
}

func (c *wsConn) Read(p []byte) (int, error) {
	// Drain leftover bytes from previous message first.
	if c.bufStart < len(c.buf) {
		n := copy(p, c.buf[c.bufStart:])
		c.bufStart += n
		return n, nil
	}

	_, data, err := c.ws.Read(context.Background())
	if err != nil {
		return 0, err
	}
	n := copy(p, data)
	if n < len(data) {
		c.buf = data
		c.bufStart = n
	} else {
		c.buf = nil
		c.bufStart = 0
	}
	return n, nil
}

func (c *wsConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	err := c.ws.Write(context.Background(), websocket.MessageBinary, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wsConn) Close() error {
	return c.ws.Close(websocket.StatusNormalClosure, "")
}

func (c *wsConn) SetDeadline(t time.Time) error      { return nil }
func (c *wsConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *wsConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *wsConn) LocalAddr() net.Addr  { return &net.TCPAddr{} }
func (c *wsConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.ParseIP("0.0.0.0")} }
