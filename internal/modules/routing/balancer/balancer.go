package balancer

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/logger"
)

var log = logger.Module("balancer")

const (
	ModuleName    = "routing.balancer"
	ModuleVersion = "1.0.0"

	defaultHealthCheckInterval = 30 * time.Second
	defaultHealthCheckTimeout  = 5 * time.Second
	defaultUnhealthyThreshold  = 3
	defaultHealthyThreshold    = 2
)

type Strategy string

const (
	StrategyRoundRobin Strategy = "round_robin"
	StrategyRandom     Strategy = "random"
	StrategyWeighted   Strategy = "weighted"
	StrategyLatency    Strategy = "latency"
	StrategyLeastConn  Strategy = "least_conn"
	StrategyIPHash     Strategy = "ip_hash"
	StrategyFailover   Strategy = "failover"
)

type ServerState int

const (
	StateUnknown   ServerState = 0
	StateHealthy   ServerState = 1
	StateUnhealthy ServerState = 2
	StateDraining  ServerState = 3
)

type Server struct {
	Address  string
	Weight   int
	Priority int
	Tags     map[string]string

	state ServerState
	mu    sync.RWMutex

	latency    time.Duration
	latencies  []time.Duration
	activeConn int32
	totalConn  uint64
	failures   uint32
	successes  uint32

	lastCheck   time.Time
	lastSuccess time.Time
	lastFailure time.Time
}

func NewServer(address string, weight int) *Server {
	if weight <= 0 {
		weight = 1
	}
	return &Server{
		Address:   address,
		Weight:    weight,
		state:     StateUnknown,
		latencies: make([]time.Duration, 0, 100),
		Tags:      make(map[string]string),
	}
}

func (s *Server) GetState() ServerState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

func (s *Server) SetState(state ServerState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
}

func (s *Server) GetLatency() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.latency
}

func (s *Server) AddLatencySample(latency time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.latencies = append(s.latencies, latency)
	if len(s.latencies) > 100 {
		s.latencies = s.latencies[1:]
	}

	if len(s.latencies) == 1 {
		s.latency = latency
	} else {
		s.latency = time.Duration(float64(s.latency)*0.8 + float64(latency)*0.2)
	}
}

func (s *Server) RecordSuccess() {
	atomic.AddUint32(&s.successes, 1)
	atomic.StoreUint32(&s.failures, 0)
	s.mu.Lock()
	s.lastSuccess = time.Now()
	s.mu.Unlock()
}

func (s *Server) RecordFailure() {
	atomic.AddUint32(&s.failures, 1)
	s.mu.Lock()
	s.lastFailure = time.Now()
	s.mu.Unlock()
}

type Config struct {
	Strategy Strategy

	Servers []*Server

	HealthCheckEnabled  bool
	HealthCheckInterval time.Duration
	HealthCheckTimeout  time.Duration
	HealthCheckPath     string
	UnhealthyThreshold  int
	HealthyThreshold    int

	LatencyWindowSize int
	LatencyThreshold  time.Duration

	FailoverOnError bool
	MaxRetries      int

	StickySession  bool
	SessionTimeout time.Duration
}

func DefaultConfig() *Config {
	return &Config{
		Strategy:            StrategyLatency,
		HealthCheckEnabled:  true,
		HealthCheckInterval: defaultHealthCheckInterval,
		HealthCheckTimeout:  defaultHealthCheckTimeout,
		UnhealthyThreshold:  defaultUnhealthyThreshold,
		HealthyThreshold:    defaultHealthyThreshold,
		LatencyWindowSize:   100,
		LatencyThreshold:    500 * time.Millisecond,
		FailoverOnError:     true,
		MaxRetries:          3,
		StickySession:       false,
		SessionTimeout:      5 * time.Minute,
	}
}

type Balancer struct {
	*base.Module
	config *Config

	mu      sync.RWMutex
	servers []*Server

	rrIndex uint64

	sessions sync.Map

	weightedServers []string
	totalWeight     int

	healthChecker *HealthChecker
	stopCh        chan struct{}
}

func New(cfg *Config) (*Balancer, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	b := &Balancer{
		Module:  base.NewModule(ModuleName, ModuleVersion, nil),
		config:  cfg,
		servers: cfg.Servers,
		stopCh:  make(chan struct{}),
	}

	b.rebuildWeightedList()

	if cfg.HealthCheckEnabled {
		b.healthChecker = NewHealthChecker(b, cfg)
	}

	return b, nil
}

func (b *Balancer) rebuildWeightedList() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.weightedServers = nil
	b.totalWeight = 0

	for _, s := range b.servers {
		if s.GetState() != StateUnhealthy {
			for i := 0; i < s.Weight; i++ {
				b.weightedServers = append(b.weightedServers, s.Address)
			}
			b.totalWeight += s.Weight
		}
	}
}

func (b *Balancer) Select(ctx context.Context, clientIP string) (*Server, error) {
	b.mu.RLock()
	servers := b.servers
	b.mu.RUnlock()

	healthy := make([]*Server, 0, len(servers))
	for _, s := range servers {
		if s.GetState() != StateUnhealthy {
			healthy = append(healthy, s)
		}
	}

	if len(healthy) == 0 {
		return nil, fmt.Errorf("no healthy servers available")
	}

	if b.config.StickySession {
		if addr, ok := b.sessions.Load(clientIP); ok {
			for _, s := range healthy {
				if s.Address == addr.(string) {
					return s, nil
				}
			}
		}
	}

	var selected *Server

	switch b.config.Strategy {
	case StrategyRoundRobin:
		selected = b.selectRoundRobin(healthy)
	case StrategyRandom:
		selected = b.selectRandom(healthy)
	case StrategyWeighted:
		selected = b.selectWeighted(healthy)
	case StrategyLatency:
		selected = b.selectLatency(healthy)
	case StrategyLeastConn:
		selected = b.selectLeastConn(healthy)
	case StrategyIPHash:
		selected = b.selectIPHash(healthy, clientIP)
	case StrategyFailover:
		selected = b.selectFailover(healthy)
	default:
		selected = b.selectRoundRobin(healthy)
	}

	if selected == nil {
		return nil, fmt.Errorf("failed to select server")
	}

	if b.config.StickySession {
		b.sessions.Store(clientIP, selected.Address)
		go func() {
			time.Sleep(b.config.SessionTimeout)
			b.sessions.Delete(clientIP)
		}()
	}

	return selected, nil
}

func (b *Balancer) selectRoundRobin(servers []*Server) *Server {
	idx := atomic.AddUint64(&b.rrIndex, 1) - 1
	return servers[idx%uint64(len(servers))]
}

func (b *Balancer) selectRandom(servers []*Server) *Server {
	return servers[rand.Intn(len(servers))]
}

func (b *Balancer) selectWeighted(servers []*Server) *Server {
	totalWeight := 0
	for _, s := range servers {
		totalWeight += s.Weight
	}

	if totalWeight == 0 {
		return servers[0]
	}

	r := rand.Intn(totalWeight)
	for _, s := range servers {
		r -= s.Weight
		if r < 0 {
			return s
		}
	}

	return servers[0]
}

func (b *Balancer) selectLatency(servers []*Server) *Server {
	sorted := make([]*Server, len(servers))
	copy(sorted, servers)
	sort.Slice(sorted, func(i, j int) bool {
		li := sorted[i].GetLatency()
		lj := sorted[j].GetLatency()
		if li == 0 && lj > 0 {
			return false
		}
		if lj == 0 && li > 0 {
			return true
		}
		return li < lj
	})

	threshold := b.config.LatencyThreshold / 10
	candidates := make([]*Server, 0)
	best := sorted[0].GetLatency()

	for _, s := range sorted {
		l := s.GetLatency()
		if l == 0 || l <= best+threshold {
			candidates = append(candidates, s)
		}
	}

	if len(candidates) == 0 {
		return sorted[0]
	}

	return candidates[rand.Intn(len(candidates))]
}

func (b *Balancer) selectLeastConn(servers []*Server) *Server {
	var selected *Server
	minConn := int32(1<<31 - 1)

	for _, s := range servers {
		conn := atomic.LoadInt32(&s.activeConn)
		adjusted := conn * 100 / int32(s.Weight)
		if adjusted < minConn {
			minConn = adjusted
			selected = s
		}
	}

	if selected == nil {
		return servers[0]
	}

	return selected
}

func (b *Balancer) selectIPHash(servers []*Server, clientIP string) *Server {
	hash := uint32(0)
	for _, c := range clientIP {
		hash = hash*31 + uint32(c)
	}
	return servers[hash%uint32(len(servers))]
}

func (b *Balancer) selectFailover(servers []*Server) *Server {
	sorted := make([]*Server, len(servers))
	copy(sorted, servers)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})

	return sorted[0]
}

func (b *Balancer) Dial(ctx context.Context, clientIP string) (net.Conn, *Server, error) {
	var lastErr error

	for retry := 0; retry <= b.config.MaxRetries; retry++ {
		server, err := b.Select(ctx, clientIP)
		if err != nil {
			return nil, nil, err
		}

		atomic.AddInt32(&server.activeConn, 1)
		atomic.AddUint64(&server.totalConn, 1)

		start := time.Now()

		conn, err := (&net.Dialer{Timeout: b.config.HealthCheckTimeout}).DialContext(context.Background(), "tcp", server.Address)
		if err != nil {
			atomic.AddInt32(&server.activeConn, -1)
			server.RecordFailure()

			if atomic.LoadUint32(&server.failures) >= uint32(b.config.UnhealthyThreshold) {
				server.SetState(StateUnhealthy)
				log.Warn("Server %s marked unhealthy", server.Address)
			}

			lastErr = err

			if b.config.FailoverOnError {
				continue
			}
			return nil, nil, err
		}

		latency := time.Since(start)
		server.AddLatencySample(latency)
		server.RecordSuccess()

		return &trackedConn{
			Conn:   conn,
			server: server,
		}, server, nil
	}

	return nil, nil, fmt.Errorf("all retries failed: %w", lastErr)
}

type trackedConn struct {
	net.Conn
	server *Server
	closed atomic.Bool
}

func (c *trackedConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		atomic.AddInt32(&c.server.activeConn, -1)
	}
	return c.Conn.Close()
}

func (b *Balancer) AddServer(server *Server) {
	b.mu.Lock()
	b.servers = append(b.servers, server)
	b.mu.Unlock()
	b.rebuildWeightedList()
}

func (b *Balancer) RemoveServer(address string) {
	b.mu.Lock()
	for i, s := range b.servers {
		if s.Address == address {
			b.servers = append(b.servers[:i], b.servers[i+1:]...)
			break
		}
	}
	b.mu.Unlock()
	b.rebuildWeightedList()
}

func (b *Balancer) GetServers() []*Server {
	b.mu.RLock()
	defer b.mu.RUnlock()
	result := make([]*Server, len(b.servers))
	copy(result, b.servers)
	return result
}

type HealthChecker struct {
	balancer *Balancer
	config   *Config
	stopCh   chan struct{}
}

func NewHealthChecker(b *Balancer, cfg *Config) *HealthChecker {
	return &HealthChecker{
		balancer: b,
		config:   cfg,
		stopCh:   make(chan struct{}),
	}
}

func (h *HealthChecker) Start() {
	go h.run()
}

func (h *HealthChecker) Stop() {
	close(h.stopCh)
}

func (h *HealthChecker) run() {
	ticker := time.NewTicker(h.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-h.stopCh:
			return
		case <-ticker.C:
			h.checkAll()
		}
	}
}

func (h *HealthChecker) checkAll() {
	servers := h.balancer.GetServers()

	var wg sync.WaitGroup
	for _, server := range servers {
		wg.Add(1)
		go func(s *Server) {
			defer wg.Done()
			h.check(s)
		}(server)
	}
	wg.Wait()

	h.balancer.rebuildWeightedList()
}

func (h *HealthChecker) check(server *Server) {
	start := time.Now()

	conn, err := (&net.Dialer{Timeout: h.config.HealthCheckTimeout}).DialContext(context.Background(), "tcp", server.Address)
	if err != nil {
		server.RecordFailure()

		failures := atomic.LoadUint32(&server.failures)
		if failures >= uint32(h.config.UnhealthyThreshold) {
			if server.GetState() != StateUnhealthy {
				server.SetState(StateUnhealthy)
				log.Warn("Server %s marked unhealthy after %d failures", server.Address, failures)
			}
		}
		return
	}
	conn.Close()

	latency := time.Since(start)
	server.AddLatencySample(latency)
	server.RecordSuccess()

	successes := atomic.LoadUint32(&server.successes)
	if successes >= uint32(h.config.HealthyThreshold) {
		if server.GetState() != StateHealthy {
			server.SetState(StateHealthy)
			log.Info("Server %s marked healthy (latency: %v)", server.Address, latency)
		}
	}

	server.mu.Lock()
	server.lastCheck = time.Now()
	server.mu.Unlock()
}


func (b *Balancer) Init(ctx context.Context) error {
	return nil
}

func (b *Balancer) Start(ctx context.Context) error {
	if b.healthChecker != nil {
		b.healthChecker.Start()
	}
	return nil
}

func (b *Balancer) Stop(ctx context.Context) error {
	close(b.stopCh)
	if b.healthChecker != nil {
		b.healthChecker.Stop()
	}
	return nil
}

func (b *Balancer) Stats() map[string]interface{} {
	servers := b.GetServers()

	serverStats := make([]map[string]interface{}, len(servers))
	for i, s := range servers {
		serverStats[i] = map[string]interface{}{
			"address":     s.Address,
			"state":       s.GetState(),
			"weight":      s.Weight,
			"latency_ms":  s.GetLatency().Milliseconds(),
			"active_conn": atomic.LoadInt32(&s.activeConn),
			"total_conn":  atomic.LoadUint64(&s.totalConn),
			"failures":    atomic.LoadUint32(&s.failures),
		}
	}

	return map[string]interface{}{
		"strategy": string(b.config.Strategy),
		"servers":  serverStats,
	}
}
