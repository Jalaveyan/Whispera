package failover

import (
	"context"
	"net"
	"sync"
	"time"

	"whispera/internal/logger"
)

var log = logger.Module("failover")

type ServerStatus struct {
	Address      string
	IsHealthy    bool
	Latency      time.Duration
	LastChecked  time.Time
	FailureCount int
}

type Config struct {
	PrimaryServer   string
	FallbackServers []string
	CheckInterval   time.Duration
	Timeout         time.Duration
	MaxRetries      int
}

type Manager struct {
	mu           sync.RWMutex
	config       *Config
	servers      map[string]*ServerStatus
	activeServer string

	onServerChange func(newServer string)

	ctx    context.Context
	cancel context.CancelFunc

	healthCheckJobs chan string
	workers         int
}
func New(cfg *Config) *Manager {
	if cfg.CheckInterval == 0 {
		cfg.CheckInterval = 30 * time.Second
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())

	workerCount := 4
	if len(cfg.FallbackServers)+1 < 4 {
		workerCount = len(cfg.FallbackServers) + 1
	}

	m := &Manager{
		config:          cfg,
		servers:         make(map[string]*ServerStatus),
		activeServer:    cfg.PrimaryServer,
		ctx:             ctx,
		cancel:          cancel,
		healthCheckJobs: make(chan string, 16),
		workers:         workerCount,
	}

	allServers := append([]string{cfg.PrimaryServer}, cfg.FallbackServers...)
	for _, addr := range allServers {
		if addr != "" {
			m.servers[addr] = &ServerStatus{
				Address:   addr,
				IsHealthy: true,
			}
		}
	}

	return m
}

func (m *Manager) Start() {
	for i := 0; i < m.workers; i++ {
		go m.healthCheckWorker()
	}
	go m.monitorLoop()
	log.Info("Failover manager started (Primary: %s, Fallbacks: %d, Workers: %d)",
		m.config.PrimaryServer, len(m.config.FallbackServers), m.workers)
}

func (m *Manager) Stop() {
	m.cancel()
}
func (m *Manager) GetActiveServer() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.activeServer
}

func (m *Manager) ReportFailure(err error) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	current := m.activeServer
	if status, exists := m.servers[current]; exists {
		status.IsHealthy = false
		status.FailureCount++
		status.LastChecked = time.Now()
		log.Warn("Server %s reported failure: %v (Count: %d)", current, err, status.FailureCount)
	}

	if m.servers[current].FailureCount >= m.config.MaxRetries {
		return m.selectBestServer()
	}

	return current
}

func (m *Manager) monitorLoop() {
	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.checkAllServers()
		}
	}
}

func (m *Manager) healthCheckWorker() {
	for {
		select {
		case <-m.ctx.Done():
			return
		case addr := <-m.healthCheckJobs:
			latency, healthy := m.pingServer(addr)

			m.mu.Lock()
			if status, ok := m.servers[addr]; ok {
				status.LastChecked = time.Now()
				status.IsHealthy = healthy
				status.Latency = latency
				if healthy {
					status.FailureCount = 0
				} else {
					status.FailureCount++
				}
			}
			m.mu.Unlock()
		}
	}
}

func (m *Manager) checkAllServers() {
	m.mu.RLock()
	servers := make([]string, 0, len(m.servers))
	for addr := range m.servers {
		servers = append(servers, addr)
	}
	m.mu.RUnlock()

	for _, addr := range servers {
		select {
		case m.healthCheckJobs <- addr:
		case <-m.ctx.Done():
			return
		default:
			log.Warn("Health check queue full, skipping %s", addr)
		}
	}

	time.Sleep(2 * time.Second)

	m.mu.Lock()
	newServer := m.selectBestServer()
	if newServer != m.activeServer {
		log.Info("Failover switching server: %s -> %s", m.activeServer, newServer)
		m.activeServer = newServer
		if m.onServerChange != nil {
			go m.onServerChange(newServer)
		}
	}
	m.mu.Unlock()
}

func (m *Manager) pingServer(addr string) (time.Duration, bool) {
	start := time.Now()

	ctx, cancel := context.WithTimeout(m.ctx, m.config.Timeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		conn, err = (&net.Dialer{Timeout: m.config.Timeout}).DialContext(ctx, "udp", addr)
		if err != nil {
			return 0, false
		}
	}
	defer conn.Close()

	return time.Since(start), true
}

func (m *Manager) selectBestServer() string {
	if p, ok := m.servers[m.config.PrimaryServer]; ok && p.IsHealthy {
		return m.config.PrimaryServer
	}

	var bestServer string
	var minLatency time.Duration = 1<<63 - 1

	for addr, status := range m.servers {
		if status.IsHealthy && status.Latency < minLatency {
			minLatency = status.Latency
			bestServer = addr
		}
	}

	if bestServer != "" {
		return bestServer
	}

	return m.config.PrimaryServer
}

func (m *Manager) OnServerChange(cb func(string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onServerChange = cb
}
