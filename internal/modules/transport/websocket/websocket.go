package websocket

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"

	"golang.org/x/net/websocket"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

const (
	ModuleName    = "transport.websocket"
	ModuleVersion = "1.0.0"
)

type Config struct {
	ListenAddr   string
	Path         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	MaxConns     int
	Origin       string
	Subprotocol  string
	UseTLS             bool
	ServerName         string
	Fingerprint        string
	InsecureSkipVerify bool
	// HostOverride sets the HTTP Host header (useful for CDN fronting).
	// When non-empty, the WebSocket Origin is derived from it too.
	HostOverride string
}

func DefaultConfig() *Config {
	return &Config{
		ListenAddr:   ":8443",
		Path:         "/ws",
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		MaxConns:     10000,
		Origin:       "*",
		Subprotocol:  "whispera",
	}
}

func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen address is required")
	}
	if c.Path == "" {
		c.Path = "/ws"
	}
	if c.MaxConns <= 0 {
		c.MaxConns = 10000
	}
	return nil
}

type Transport struct {
	*base.Module
	config     *Config
	server     *http.Server
	mu         sync.RWMutex
	acceptChan chan net.Conn

	connections sync.Map

	connCount    int64
	bytesRx      uint64
	bytesTx      uint64
	activeConns  int64
	acceptErrors uint64
}

func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	t := &Transport{
		Module:     base.NewModule(ModuleName, ModuleVersion, nil),
		config:     cfg,
		acceptChan: make(chan net.Conn, 1000),
	}

	return t, nil
}

func (t *Transport) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := t.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if wsCfg, ok := cfg.(*Config); ok {
		t.config = wsCfg
	}

	return nil
}

func (t *Transport) Start() error {
	if err := t.Module.Start(); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle(t.config.Path, websocket.Handler(t.handleWebSocket))

	t.server = &http.Server{
		Addr:         t.config.ListenAddr,
		Handler:      mux,
		ReadTimeout:  t.config.ReadTimeout,
		WriteTimeout: t.config.WriteTimeout,
	}

	go func() {
		if err := t.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.SetHealthy(false, fmt.Sprintf("server error: %v", err))
		}
	}()

	t.SetHealthy(true, fmt.Sprintf("listening on %s%s", t.config.ListenAddr, t.config.Path))
	t.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"listen_addr": t.config.ListenAddr,
		"path":        t.config.Path,
	})

	return nil
}

func (t *Transport) handleWebSocket(ws *websocket.Conn) {
	if atomic.LoadInt64(&t.activeConns) >= int64(t.config.MaxConns) {
		ws.Close()
		return
	}

	atomic.AddInt64(&t.connCount, 1)
	atomic.AddInt64(&t.activeConns, 1)

	id := atomic.LoadInt64(&t.connCount)

	wrapped := &wsConn{
		Conn:      ws,
		transport: t,
		id:        id,
	}

	t.connections.Store(id, wrapped)

	select {
	case t.acceptChan <- wrapped:
	default:
		wrapped.Close()
		return
	}

	t.UpdateActivity()

	<-wrapped.closeChan
}

func (t *Transport) Stop() error {
	t.mu.Lock()
	if t.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		t.server.Shutdown(ctx)
		t.server = nil
	}
	t.mu.Unlock()

	close(t.acceptChan)

	t.connections.Range(func(key, value interface{}) bool {
		if conn, ok := value.(*wsConn); ok {
			conn.Close()
		}
		t.connections.Delete(key)
		return true
	})

	t.PublishEvent(events.EventTypeModuleStopped, nil)
	return t.Module.Stop()
}

func (t *Transport) Type() interfaces.TransportType {
	return interfaces.TransportWebSocket
}

func (t *Transport) Listen(addr string) error {
	return nil
}

func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	return t.DialWithFingerprint(ctx, addr, t.config.Fingerprint)
}

func (t *Transport) DialWithFingerprint(ctx context.Context, addr string, fingerprint string) (net.Conn, error) {
	_ = fingerprint

	var scheme, originScheme string
	if t.config.UseTLS {
		scheme = "wss://"
		originScheme = "https://"
	} else {
		scheme = "ws://"
		originScheme = "http://"
	}

	// HostOverride allows CDN fronting: the URL uses the real server addr but
	// the HTTP Host header (and Origin) are set to the front domain.
	host := addr
	if t.config.HostOverride != "" {
		host = t.config.HostOverride
	}

	wsURL := scheme + host + t.config.Path
	origin := originScheme + host

	wsCfg, err := websocket.NewConfig(wsURL, origin)
	if err != nil {
		return nil, err
	}
	if t.config.Subprotocol != "" {
		wsCfg.Protocol = []string{t.config.Subprotocol}
	}

	// When HostOverride is set, dial the real addr but send Host: override.
	// golang.org/x/net/websocket resolves the URL host for dialing, so we
	// need to set the location to the real addr for the TCP connection.
	if t.config.HostOverride != "" {
		loc, err2 := wsCfg.Location.Parse(scheme + addr + t.config.Path)
		if err2 == nil {
			wsCfg.Location = loc
		}
	}

	var ws *websocket.Conn
	ws, err = websocket.DialConfig(wsCfg)
	if err != nil {
		return nil, err
	}

	atomic.AddInt64(&t.connCount, 1)
	atomic.AddInt64(&t.activeConns, 1)

	id := atomic.LoadInt64(&t.connCount)

	wrapped := &wsConn{
		Conn:      ws,
		transport: t,
		id:        id,
	}

	t.connections.Store(id, wrapped)

	return wrapped, nil
}

func (t *Transport) Accept() (net.Conn, error) {
	conn, ok := <-t.acceptChan
	if !ok {
		return nil, fmt.Errorf("transport stopped")
	}
	return conn, nil
}

func (t *Transport) Close() error {
	return t.Stop()
}

func (t *Transport) HealthCheck() interfaces.HealthStatus {
	status := t.Module.HealthCheck()
	status.Details["conn_count"] = atomic.LoadInt64(&t.connCount)
	status.Details["active_conns"] = atomic.LoadInt64(&t.activeConns)
	status.Details["bytes_rx"] = atomic.LoadUint64(&t.bytesRx)
	status.Details["bytes_tx"] = atomic.LoadUint64(&t.bytesTx)
	status.Details["listen_addr"] = t.config.ListenAddr
	status.Details["path"] = t.config.Path
	return status
}

type wsConn struct {
	*websocket.Conn
	transport *Transport
	id        int64
	closed    int32
	closeChan chan struct{}
}

func (c *wsConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 {
		atomic.AddUint64(&c.transport.bytesRx, uint64(n))
	}
	return
}

func (c *wsConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		atomic.AddUint64(&c.transport.bytesTx, uint64(n))
	}
	return
}

func (c *wsConn) Close() error {
	if atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		atomic.AddInt64(&c.transport.activeConns, -1)
		c.transport.connections.Delete(c.id)
		if c.closeChan != nil {
			close(c.closeChan)
		}
		return c.Conn.Close()
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
	return New(config)
}
