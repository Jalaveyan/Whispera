package socks5

import (
	"context"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/proxy"
	"whispera/internal/modules/relay"
)

const (
	ModuleName    = "socks5"
	ModuleVersion = "2.0.0"
)

type Config struct {
	ListenAddr    string
	Debug         bool
	VPNServerAddr string
	MTU           int
}

type Module struct {
	*base.Module
	config   *Config
	server   *proxy.SOCKS5Server
	listener net.Listener
	tunnel   TunnelManager
	mu       sync.RWMutex
	running  int32
}

type TunnelManager interface {
	IsConnected() bool
	OpenStream(ctx context.Context, proto byte, addr string, port uint16) (net.Conn, error)
}

func New(cfg *Config) (*Module, error) {
	if cfg == nil {
		cfg = &Config{
			ListenAddr: "127.0.0.1:10800",
		}
	}
	if cfg.MTU <= 0 || cfg.MTU > 65535 {
		cfg.MTU = 65535
	}
	return &Module{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: cfg,
	}, nil
}

func (m *Module) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	return m.Module.Init(ctx, cfg)
}

func (m *Module) Start() error {
	if err := m.Module.Start(); err != nil {
		return err
	}

	m.server = proxy.NewSOCKS5Server(m.config.ListenAddr, m.handleConnection)

	atomic.StoreInt32(&m.running, 1)

	go func() {
		backoff := 100 * time.Millisecond
		for {
			if atomic.LoadInt32(&m.running) == 0 {
				return
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						stdlog.Printf("[SOCKS5] CRITICAL PANIC in Listener: %v", r)
					}
				}()
				stdlog.Printf("[SOCKS5] Starting server on %s", m.config.ListenAddr)
				if err := m.server.ListenAndServe(); err != nil {
					if atomic.LoadInt32(&m.running) == 1 {
						stdlog.Printf("[SOCKS5] Server error: %v. Restarting in %v...", err, backoff)
					}
				}
			}()
			time.Sleep(backoff)
			if backoff < 3*time.Second {
				backoff *= 2
				if backoff > 3*time.Second {
					backoff = 3 * time.Second
				}
			}
		}
	}()

	m.SetHealthy(true, "SOCKS5 server running")
	return nil
}

func (m *Module) Stop() error {
	atomic.StoreInt32(&m.running, 0)
	m.mu.Lock()
	if m.listener != nil {
		m.listener.Close()
	}
	m.mu.Unlock()
	return m.Module.Stop()
}

func (m *Module) SetTunnel(tunnel TunnelManager) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tunnel = tunnel
	stdlog.Printf("[SOCKS5] Tunnel set")
}

func (m *Module) handleConnection(clientConn net.Conn, targetAddr string, targetPort uint16) error {
	defer func() {
		if r := recover(); r != nil {
			stdlog.Printf("[SOCKS5] PANIC in handleConnection: %v", r)
		}
	}()

	m.mu.RLock()
	tunnel := m.tunnel
	m.mu.RUnlock()

	deadline := time.Now().Add(5 * time.Second)
	for tunnel == nil || !tunnel.IsConnected() {
		if time.Now().After(deadline) {
			return fmt.Errorf("tunnel not ready")
		}
		time.Sleep(100 * time.Millisecond)
		m.mu.RLock()
		tunnel = m.tunnel
		m.mu.RUnlock()
	}

	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		tcpConn.SetReadBuffer(2 * 1024 * 1024)
		tcpConn.SetWriteBuffer(2 * 1024 * 1024)
		tcpConn.SetNoDelay(true)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := tunnel.OpenStream(ctx, 0x06, targetAddr, targetPort)
	if err != nil {
		return fmt.Errorf("relay connect: %w", err)
	}
	defer stream.Close()

	errCh := make(chan error, 2)
	go func() { _, err := io.Copy(stream, clientConn); errCh <- err }()
	go func() { _, err := io.Copy(clientConn, stream); errCh <- err }()
	<-errCh
	return nil
}
