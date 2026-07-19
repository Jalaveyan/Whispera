package apiserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/nekoskin/whispera/app/auth"
	logger "github.com/nekoskin/whispera/common/log"
	"github.com/nekoskin/whispera/common/runtime/base"
	"github.com/nekoskin/whispera/common/runtime/events"
	"github.com/nekoskin/whispera/common/runtime/interfaces"
	"github.com/nekoskin/whispera/common/runtime/registry"
	"github.com/nekoskin/whispera/core/keylimits"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

const (
	ModuleName    = "api.server"
	ModuleVersion = "1.0.0"
)

var log = logger.Module("apiserver")

type Config struct {
	Enabled           bool
	ListenAddr        string
	AuthToken         string
	WebRoot           string
	EnableCORS        bool
	AllowedOrigins    []string
	TLSCert           string
	TLSKey            string
	AdminUsername     string
	AdminPassword     string
	AdminPasswordHash string
	LoginRateLimit    int
	TLSFingerprint    string
}

type Server struct {
	*base.Module
	config      *Config
	server      *http.Server
	http3Server *http3.Server
	mux         *http.ServeMux

	registry registry.Registry

	mu       sync.RWMutex
	handlers map[string]http.HandlerFunc

	jwtManager    *auth.JWTManager
	keyLimits     *keylimits.Manager
	probeDetector interface {
		Stats() map[string]interface{}
		BlockIP(ip, reason string)
		UnblockIP(ip string)
	}

	loginAttempts   map[string][]time.Time
	loginAttemptsMu sync.Mutex

	sessionToken  string
	signingSecret []byte

	revokedTokens   map[string]time.Time
	revokedTokensMu sync.Mutex

	revokedKeys   map[string]time.Time
	revokedKeysMu sync.RWMutex

	cpuLoad float64
	cpuMu   sync.Mutex
	cpuPrev [2]uint64

	activeConns   map[string]int32
	activeConnsMu sync.Mutex
	maxConnsPerIP int

	apiRateBuckets   map[string]*apiRateBucket
	apiRateBucketsMu sync.Mutex
	apiRateClean     time.Time

	inflight  sync.WaitGroup
	startTime time.Time
}

type ctxKey int

const ctxKeyClaims ctxKey = 1

func GetClaims(r *http.Request) *auth.Claims {
	if c, ok := r.Context().Value(ctxKeyClaims).(*auth.Claims); ok {
		return c
	}
	return nil
}

func DefaultConfig() *Config {
	return &Config{
		Enabled:    true,
		ListenAddr: ":8081",
		EnableCORS: true,
	}
}

var weakPasswords = map[string]struct{}{
	"admin": {}, "password": {}, "12345678": {}, "qwerty": {},
	"whispera": {}, "changeme": {}, "secret": {}, "letmein": {},
}

func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		c.ListenAddr = ":8081"
	}
	if c.AdminPasswordHash == "" {
		if p := c.AdminPassword; p != "" {
			if len(p) < 12 {
				return fmt.Errorf("admin_password is too short (minimum 12 characters) — generate one with: openssl rand -base64 16")
			}
			if _, weak := weakPasswords[strings.ToLower(p)]; weak {
				return fmt.Errorf("admin_password %q is a known default — change it in config.yaml", p)
			}
		}
	}
	return nil
}

func New(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	if err := os.MkdirAll("/etc/whispera", 0755); err != nil {
		log.Warn("mkdir /etc/whispera: %v", err)
	}

	loadUsers()
	startUserStoreWatcher()
	loadSubscriptions()

	sessionToken := loadOrCreateSessionToken()
	signingSecret := loadOrCreateSigningSecret()

	s := &Server{
		Module:         base.NewModule(ModuleName, ModuleVersion, nil),
		config:         cfg,
		mux:            http.NewServeMux(),
		handlers:       make(map[string]http.HandlerFunc),
		jwtManager:     auth.NewJWTManager(signingSecret),
		loginAttempts:  make(map[string][]time.Time),
		sessionToken:   sessionToken,
		signingSecret:  signingSecret,
		revokedTokens:  make(map[string]time.Time),
		revokedKeys:    make(map[string]time.Time),
		activeConns:    make(map[string]int32),
		maxConnsPerIP:  50,
		apiRateBuckets: make(map[string]*apiRateBucket),
		apiRateClean:   time.Now(),
	}

	s.loadRevokedKeys()
	s.registerDefaultRoutes()
	go s.cpuSampler()

	s.registerUserV2Routes()

	return s, nil
}

func (s *Server) SetKeyLimits(m *keylimits.Manager) {
	s.keyLimits = m
}

func (s *Server) handleDisabledEndpoint(w http.ResponseWriter, r *http.Request) {
	http.Error(w, `{"error":"endpoint disabled"}`, http.StatusForbidden)
}

func (s *Server) registerDefaultRoutes() {
	s.Handle("POST /api/login", s.handleLogin)
	s.Handle("POST /api/auth/login", s.handleDisabledEndpoint)
	s.Handle("POST /api/logout", s.handleLogout)
	s.Handle("POST /api/v2/auth/login", s.handleLoginV2)
	s.Handle("POST /api/v2/auth/refresh", s.handleRefreshToken)
	s.Handle("POST /api/v2/auth/logout", s.handleLogoutV2)

	s.Handle("GET /api/v1/health", s.handleHealth)
	s.Handle("GET /api/v1/status", s.handleStatus)
	s.Handle("GET /api/v1/modules", s.handleDisabledEndpoint)
	s.Handle("GET /api/v1/config", s.handleGetConfig)

	s.Handle("POST /api/v1/config/update", s.handleDisabledEndpoint)
	s.Handle("POST /api/v1/config/reload", s.handleDisabledEndpoint)
	s.Handle("GET /api/v1/sessions", s.handleDisabledEndpoint)
	s.Handle("DELETE /api/v1/sessions/{id}", s.handleDisabledEndpoint)
	s.Handle("GET /api/v1/stats", s.handleDisabledEndpoint)
	s.Handle("GET /api/v1/system/info", s.handleDisabledEndpoint)
	s.Handle("GET /api/v1/stats/traffic", s.handleTrafficStats)
	s.Handle("GET /api/v1/stats/users", s.handleDisabledEndpoint)

	s.Handle("GET /api/v1/dhcp/status", s.handleDisabledEndpoint)
	s.Handle("GET /api/v1/dhcp/leases", s.handleDisabledEndpoint)
	s.Handle("DELETE /api/v1/dhcp/lease", s.handleDisabledEndpoint)
	s.Handle("GET /api/users", s.handleDisabledEndpoint)
	s.Handle("POST /api/users/add", s.handleDisabledEndpoint)
	s.Handle("POST /api/users", s.handleDisabledEndpoint)
	s.Handle("PUT /api/users/{id}", s.handleDisabledEndpoint)
	s.Handle("POST /api/users/delete", s.handleDisabledEndpoint)

	s.Handle("GET /api/routing/rules", s.handleDisabledEndpoint)
	s.Handle("POST /api/routing/rules/add", s.handleDisabledEndpoint)
	s.Handle("POST /api/routing/rules/delete", s.handleDisabledEndpoint)
	s.Handle("GET /api/outbounds", s.handleGetOutbounds)
	s.Handle("POST /api/outbounds/add", s.handleAddOutbound)
	s.Handle("POST /api/outbounds/delete", s.handleDeleteOutbound)

	s.Handle("GET /api/inbounds", s.handleDisabledEndpoint)
	s.Handle("GET /api/inbounds/pubkey", s.handleDisabledEndpoint)
	s.Handle("POST /api/inbounds/add", s.handleDisabledEndpoint)
	s.Handle("POST /api/inbounds/update", s.handleDisabledEndpoint)
	s.Handle("POST /api/inbounds/delete", s.handleDisabledEndpoint)

	s.Handle("POST /api/keys/generate", s.handleDisabledEndpoint)
	s.Handle("POST /api/keys/connection", s.handleDisabledEndpoint)
	s.Handle("POST /api/keys/transport", s.handleDisabledEndpoint)
	s.Handle("POST /api/keys/multi-transport", s.handleDisabledEndpoint)
	s.Handle("POST /api/keys/revoke", s.handleDisabledEndpoint)
	s.Handle("GET /api/keys/revoked", s.handleDisabledEndpoint)
	s.Handle("POST /api/keys/check", s.handleDisabledEndpoint)
	s.Handle("GET /api/keys/ping", s.handleDisabledEndpoint)
	s.Handle("GET /api/keys/ping/all", s.handleDisabledEndpoint)

	s.Handle("GET /api/key-limits", s.handleDisabledEndpoint)
	s.Handle("GET /api/key-limits/{id}", s.handleDisabledEndpoint)
	s.Handle("POST /api/key-limits/{id}", s.handleDisabledEndpoint)
	s.Handle("DELETE /api/key-limits/{id}", s.handleDisabledEndpoint)
	s.Handle("GET /api/key-limits-defaults", s.handleDisabledEndpoint)
	s.Handle("POST /api/key-limits-defaults", s.handleDisabledEndpoint)

	s.Handle("GET /api/subscriptions", s.handleDisabledEndpoint)
	s.Handle("POST /api/subscriptions/add", s.handleDisabledEndpoint)
	s.Handle("POST /api/subscriptions/update", s.handleDisabledEndpoint)
	s.Handle("POST /api/subscriptions/delete", s.handleDisabledEndpoint)
	s.Handle("GET /sub/{token}", s.handleServeSubscription)

	s.Handle("GET /api/firewall/status", s.handleDisabledEndpoint)
	s.Handle("POST /api/firewall/rules", s.handleDisabledEndpoint)
	s.Handle("DELETE /api/firewall/rules", s.handleDisabledEndpoint)
	s.Handle("POST /api/firewall/toggle", s.handleDisabledEndpoint)
	s.Handle("GET /api/backup", s.handleGetBackup)
	s.Handle("GET /api/backup/full", s.handleGetBackupFull)
	s.Handle("GET /api/backup/list", s.handleBackupList)
	s.Handle("POST /api/backup/restore", s.handleRestoreBackup)

	s.Handle("GET /api/sessions", s.handleDisabledEndpoint)
	s.Handle("POST /api/sessions/{id}/kill", s.handleDisabledEndpoint)
	s.Handle("GET /api/stats", s.handleDisabledEndpoint)
	s.Handle("GET /api/stats/live", s.handleDisabledEndpoint)
	s.Handle("GET /api/stats/traffic", s.handleDisabledEndpoint)
	s.Handle("GET /api/stats/user/{id}", s.handleDisabledEndpoint)

	s.Handle("GET /api/system/info", s.handleDisabledEndpoint)
	s.Handle("POST /api/admin/update", s.handleDisabledEndpoint)
	s.Handle("GET /api/system/update-check", s.handleDisabledEndpoint)
	s.Handle("GET /api/logs", s.handleGetLogs)

	s.Handle("GET /api/ml/config", s.handleDisabledEndpoint)
	s.Handle("POST /api/ml/token/rotate", s.handleDisabledEndpoint)
	s.Handle("GET /api/events", s.handleDisabledEndpoint)

	s.Handle("GET /api/fingerprints", s.handleGetFingerprints)
	s.Handle("POST /api/fingerprints/set", s.handleSetFingerprint)
	s.Handle("GET /api/failover/status", s.handleDisabledEndpoint)

	s.Handle("GET /api/v1/speed/ping", s.handleDisabledEndpoint)
	s.Handle("GET /api/v1/speed/download", s.handleDisabledEndpoint)
	s.Handle("POST /api/v1/speed/upload", s.handleDisabledEndpoint)
}

func (s *Server) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := s.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if apiCfg, ok := cfg.(*Config); ok {
		s.config = apiCfg
	}

	return nil
}

func (s *Server) Start() error {
	if err := s.Module.Start(); err != nil {
		return err
	}

	s.startTime = time.Now()

	go s.pruneLoginAttemptsLoop(s.Module.Context())

	if !s.config.Enabled {
		s.SetHealthy(true, "API server disabled")
		return nil
	}

	handler := s.buildHandler()

	s.server = &http.Server{
		Addr:         s.config.ListenAddr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
		TLSConfig:    &tls.Config{MinVersion: tls.VersionTLS12},
	}

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", s.config.ListenAddr)
	if err != nil {
		errMsg := fmt.Sprintf("failed to bind to %s: %v", s.config.ListenAddr, err)
		s.SetHealthy(false, errMsg)
		return fmt.Errorf("failed to bind API server to %s: %w", s.config.ListenAddr, err)
	}

	log.Printf("listening on %s", s.config.ListenAddr)

	go s.serveHTTP(ln)
	s.startHTTP3(handler)
	go s.cleanupRevokedTokensLoop()

	s.SetHealthy(true, fmt.Sprintf("API server running on %s", s.config.ListenAddr))
	s.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"listen_addr": s.config.ListenAddr,
	})

	return nil
}

func (s *Server) pruneLoginAttemptsLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.pruneLoginAttempts()
		case <-ctx.Done():
			return
		}
	}
}

func (s *Server) pruneLoginAttempts() {
	cutoff := time.Now().Add(-2 * time.Minute)
	s.loginAttemptsMu.Lock()
	defer s.loginAttemptsMu.Unlock()
	for ip, attempts := range s.loginAttempts {
		var fresh []time.Time
		for _, t := range attempts {
			if t.After(cutoff) {
				fresh = append(fresh, t)
			}
		}
		if len(fresh) == 0 {
			delete(s.loginAttempts, ip)
		} else {
			s.loginAttempts[ip] = fresh
		}
	}
}

func (s *Server) serveHTTP(ln net.Listener) {
	var serveErr error
	if s.config.TLSCert != "" && s.config.TLSKey != "" {
		serveErr = s.server.ServeTLS(ln, s.config.TLSCert, s.config.TLSKey)
	} else {
		serveErr = s.server.Serve(ln)
	}
	if serveErr != nil && serveErr != http.ErrServerClosed {
		log.Error("HTTP server error: %v", serveErr)
		s.SetHealthy(false, fmt.Sprintf("HTTP server error: %v", serveErr))
	}
}

func (s *Server) startHTTP3(handler http.Handler) {
	if s.config.TLSCert == "" || s.config.TLSKey == "" {
		return
	}
	s.http3Server = &http3.Server{
		Addr:    s.config.ListenAddr,
		Handler: handler,
	}
	go func() {
		_ = s.http3Server.ListenAndServeTLS(s.config.TLSCert, s.config.TLSKey)
	}()
}

func (s *Server) cleanupRevokedTokensLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.cleanupRevokedTokens()
	}
}

func (s *Server) Stop() error {
	if s.http3Server != nil {
		s.http3Server.Close()
	}
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		s.server.Shutdown(ctx)

		done := make(chan struct{})
		go func() { s.inflight.Wait(); close(done) }()
		select {
		case <-done:
		case <-ctx.Done():
		}
	}

	s.PublishEvent(events.EventTypeModuleStopped, nil)
	return s.Module.Stop()
}

func (s *Server) SetRegistry(reg registry.Registry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.registry = reg
}

func (s *Server) Handle(pattern string, handler http.HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[pattern] = handler
}

func (s *Server) buildHandler() http.Handler {
	var rootHandler http.Handler
	if s.config.WebRoot != "" {
		fs := http.FileServer(http.Dir(s.config.WebRoot))
		rootHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				s.mux.ServeHTTP(w, r)
				return
			}
			fs.ServeHTTP(w, r)
		})
	} else {
		rootHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				s.mux.ServeHTTP(w, r)
				return
			}
			if r.URL.Path == "/" || r.URL.Path == "" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"name":   "Whispera API",
					"status": "running",
					"panel": "http://" + func() string {
						if i := strings.LastIndex(r.Host, ":"); i >= 0 {
							return r.Host[:i]
						}
						return r.Host
					}() + ":3000",
					"api": "/api/v1/health",
				})
				return
			}
			s.mux.ServeHTTP(w, r)
		})
	}
	s.mu.RLock()
	for pattern, handler := range s.handlers {
		s.mux.HandleFunc(pattern, handler)
	}
	s.mu.RUnlock()

	var handler http.Handler = rootHandler

	handler = s.authMiddleware(handler)

	handler = s.requestBodyLimitMiddleware(handler)

	handler = s.apiRateMiddleware(handler)

	if s.config.EnableCORS {
		handler = s.corsMiddleware(handler)
	}

	handler = s.securityHeadersMiddleware(handler)

	handler = s.loggingMiddleware(handler)

	handler = s.connLimitMiddleware(handler)

	handler = s.timeoutMiddleware(handler, 30*time.Second)

	handler = s.recoveryMiddleware(handler)

	return handler
}

func readProcStatCPU() (idle, total uint64, err error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	for _, line := range strings.SplitN(string(data), "\n", 2) {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		var name string
		var fields [10]uint64
		fmt.Sscanf(line, "%s %d %d %d %d %d %d %d %d %d %d",
			&name,
			&fields[0], &fields[1], &fields[2], &fields[3],
			&fields[4], &fields[5], &fields[6], &fields[7],
			&fields[8], &fields[9],
		)
		idle = fields[3] + fields[4]
		for _, v := range fields {
			total += v
		}
		return idle, total, nil
	}
	return 0, 0, fmt.Errorf("cpu line not found")
}

func (s *Server) cpuSampler() {
	idle0, total0, err := readProcStatCPU()
	if err != nil {
		return
	}
	s.cpuMu.Lock()
	s.cpuPrev = [2]uint64{idle0, total0}
	s.cpuMu.Unlock()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		idle1, total1, err := readProcStatCPU()
		if err != nil {
			continue
		}
		s.cpuMu.Lock()
		idleDelta := idle1 - s.cpuPrev[0]
		totalDelta := total1 - s.cpuPrev[1]
		if totalDelta > 0 {
			s.cpuLoad = (1.0 - float64(idleDelta)/float64(totalDelta)) * 100.0
		}
		s.cpuPrev = [2]uint64{idle1, total1}
		s.cpuMu.Unlock()
	}
}

func (s *Server) HealthCheck() interfaces.HealthStatus {
	status := s.Module.HealthCheck()
	status.Details["listen_addr"] = s.config.ListenAddr
	status.Details["enabled"] = s.config.Enabled

	s.mu.RLock()
	status.Details["routes_registered"] = len(s.handlers)
	s.mu.RUnlock()

	return status
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
