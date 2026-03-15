package fallback

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/interfaces"
)

type Config struct {
	TransportPriority []interfaces.TransportType

	RetryDelay time.Duration

	MaxRetries int

	BlockDetectionTimeout time.Duration

	CooldownPeriod time.Duration
}

func DefaultConfig() *Config {
	return &Config{
		TransportPriority: []interfaces.TransportType{
			interfaces.TransportH2C,
			interfaces.TransportWebSocket,
			interfaces.TransportXHTTP,
			interfaces.TransportTCP,
			interfaces.TransportQUIC,
			interfaces.TransportUDP,
		},
		RetryDelay:            500 * time.Millisecond,
		MaxRetries:            3,
		BlockDetectionTimeout: 5 * time.Second,
		CooldownPeriod:        5 * time.Minute,
	}
}

type TransportDialer interface {
	Dial(ctx context.Context, addr string) (net.Conn, error)
	Type() interfaces.TransportType
}

type Manager struct {
	config     *Config
	transports map[interfaces.TransportType]TransportDialer
	mu         sync.RWMutex

	blocked   map[interfaces.TransportType]time.Time
	blockedMu sync.RWMutex

	current interfaces.TransportType

	fallbackCount uint64
	successCount  uint64
	failureCount  uint64
}

func New(cfg *Config) *Manager {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	m := &Manager{
		config:     cfg,
		transports: make(map[interfaces.TransportType]TransportDialer),
		blocked:    make(map[interfaces.TransportType]time.Time),
	}

	if len(cfg.TransportPriority) > 0 {
		m.current = cfg.TransportPriority[0]
	}

	return m
}

func (m *Manager) RegisterTransport(t TransportDialer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.transports[t.Type()] = t
}

func (m *Manager) Dial(ctx context.Context, addr string) (net.Conn, error) {
	m.mu.RLock()
	transports := m.transports
	priority := m.config.TransportPriority
	m.mu.RUnlock()

	if len(transports) == 0 {
		return nil, errors.New("no transports registered")
	}

	var lastErr error

	for _, tType := range priority {
		transport, ok := transports[tType]
		if !ok {
			continue
		}

		if m.isBlocked(tType) {
			continue
		}

		conn, err := m.tryTransport(ctx, transport, addr)
		if err == nil {
			m.setActive(tType)
			atomic.AddUint64(&m.successCount, 1)
			return conn, nil
		}

		lastErr = err
		atomic.AddUint64(&m.failureCount, 1)

		if m.shouldMarkBlocked(err) {
			m.markBlocked(tType)
			atomic.AddUint64(&m.fallbackCount, 1)
		}
	}

	return nil, fmt.Errorf("all transports failed, last error: %w", lastErr)
}

func (m *Manager) tryTransport(ctx context.Context, t TransportDialer, addr string) (net.Conn, error) {
	var lastErr error

	for i := 0; i < m.config.MaxRetries; i++ {
		dialCtx, cancel := context.WithTimeout(ctx, m.config.BlockDetectionTimeout)

		conn, err := t.Dial(dialCtx, addr)
		cancel()

		if err == nil {
			return conn, nil
		}

		lastErr = err

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		if i < m.config.MaxRetries-1 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(m.config.RetryDelay):
			}
		}
	}

	return nil, lastErr
}

func (m *Manager) isBlocked(t interfaces.TransportType) bool {
	m.blockedMu.RLock()
	blockedTime, blocked := m.blocked[t]
	m.blockedMu.RUnlock()

	if !blocked {
		return false
	}

	if time.Since(blockedTime) > m.config.CooldownPeriod {
		m.blockedMu.Lock()
		delete(m.blocked, t)
		m.blockedMu.Unlock()
		return false
	}

	return true
}

func (m *Manager) markBlocked(t interfaces.TransportType) {
	m.blockedMu.Lock()
	m.blocked[t] = time.Now()
	m.blockedMu.Unlock()
}

func (m *Manager) shouldMarkBlocked(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	blockIndicators := []string{
		"connection reset",
		"connection refused",
		"tls: handshake failure",
		"tls: protocol version",
		"i/o timeout",
		"network is unreachable",
		"no route to host",
		"connection timed out",
	}

	for _, indicator := range blockIndicators {
		if contains(errStr, indicator) {
			return true
		}
	}

	return false
}

func (m *Manager) setActive(t interfaces.TransportType) {
	m.mu.Lock()
	m.current = t
	m.mu.Unlock()
}

func (m *Manager) GetActive() interfaces.TransportType {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

func (m *Manager) GetBlockedTransports() []interfaces.TransportType {
	m.blockedMu.RLock()
	defer m.blockedMu.RUnlock()

	result := make([]interfaces.TransportType, 0, len(m.blocked))
	for t := range m.blocked {
		result = append(result, t)
	}
	return result
}

func (m *Manager) UnblockAll() {
	m.blockedMu.Lock()
	m.blocked = make(map[interfaces.TransportType]time.Time)
	m.blockedMu.Unlock()
}

func (m *Manager) Stats() (fallbacks, successes, failures uint64) {
	return atomic.LoadUint64(&m.fallbackCount),
		atomic.LoadUint64(&m.successCount),
		atomic.LoadUint64(&m.failureCount)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsLower(s, substr))
}

func containsLower(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if equalFoldSlice(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

func equalFoldSlice(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
