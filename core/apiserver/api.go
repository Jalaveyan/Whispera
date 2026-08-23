package apiserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	logger "github.com/nekoskin/whispera/common/log"
	"github.com/nekoskin/whispera/common/runtime/base"
	"github.com/nekoskin/whispera/common/runtime/events"
	"github.com/nekoskin/whispera/common/runtime/interfaces"
	"github.com/nekoskin/whispera/common/runtime/registry"
	"github.com/nekoskin/whispera/core/config"
	"github.com/nekoskin/whispera/core/keylimits"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

const (
	ModuleName    = "api.server"
	ModuleVersion = "1.0.0"
)

var log = logger.Module("apiserver")

type Config struct {
	Enabled        bool
	ListenAddr     string
	AuthToken      string
	WebRoot        string
	EnableCORS     bool
	AllowedOrigins []string
	TLSCert        string
	TLSKey         string
	TLSFingerprint string
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

	keyLimits     *keylimits.Manager
	revokedKeys   map[string]time.Time
	revokedKeysMu sync.RWMutex

	activeConns   map[string]int32
	activeConnsMu sync.Mutex
	maxConnsPerIP int

	apiRateBuckets   map[string]*apiRateBucket
	apiRateBucketsMu sync.Mutex
	apiRateClean     time.Time

	inflight  sync.WaitGroup
	startTime time.Time
}

func DefaultConfig() *Config {
	return &Config{
		Enabled:    true,
		ListenAddr: ":8081",
		EnableCORS: true,
	}
}

func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		c.ListenAddr = ":8081"
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

	if err := os.MkdirAll(config.Dir, 0755); err != nil {
		log.Warn("mkdir /etc/whispera: %v", err)
	}

	loadUsers()
	startUserStoreWatcher()
	loadSubscriptions()

	s := &Server{
		Module:         base.NewModule(ModuleName, ModuleVersion, nil),
		config:         cfg,
		mux:            http.NewServeMux(),
		handlers:       make(map[string]http.HandlerFunc),
		revokedKeys:    make(map[string]time.Time),
		activeConns:    make(map[string]int32),
		maxConnsPerIP:  50,
		apiRateBuckets: make(map[string]*apiRateBucket),
		apiRateClean:   time.Now(),
	}

	s.loadRevokedKeys()
	s.registerDefaultRoutes()

	return s, nil
}

func (s *Server) SetKeyLimits(m *keylimits.Manager) {
	s.keyLimits = m
}

func (s *Server) registerDefaultRoutes() {
	s.Handle("GET /api/v1/health", s.handleHealth)
	s.Handle("GET /api/v1/status", s.handleStatus)
	s.Handle("GET /api/v1/config", s.handleGetConfig)

	s.Handle("GET /api/outbounds", s.handleGetOutbounds)
	s.Handle("POST /api/outbounds/add", s.handleAddOutbound)
	s.Handle("POST /api/outbounds/delete", s.handleDeleteOutbound)

	s.Handle("GET /sub/{token}", s.handleServeSubscription)

	s.Handle("GET /api/backup", s.handleGetBackup)
	s.Handle("POST /api/backup/restore", s.handleRestoreBackup)

	s.Handle("GET /api/logs", s.handleGetLogs)

	s.Handle("GET /api/fingerprints", s.handleGetFingerprints)
	s.Handle("POST /api/fingerprints/set", s.handleSetFingerprint)
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

	s.SetHealthy(true, fmt.Sprintf("API server running on %s", s.config.ListenAddr))
	s.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"listen_addr": s.config.ListenAddr,
	})

	return nil
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
					"api":    "/api/v1/health",
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

func (s *Server) HealthCheck() interfaces.HealthStatus {
	status := s.Module.HealthCheck()
	status.Details["listen_addr"] = s.config.ListenAddr
	status.Details["enabled"] = s.config.Enabled

	s.mu.RLock()
	status.Details["routes_registered"] = len(s.handlers)
	s.mu.RUnlock()

	return status
}
