package camouflage

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/logger"
)

var log = logger.Module("camouflage")

const (
	ModuleName    = "camouflage"
	ModuleVersion = "1.0.0"
)

type Config struct {
	ListenAddr    string
	AuthSecret    []byte
	CoverSiteURL  string
	StaticDir     string
	TLSCertFile   string
	TLSKeyFile    string
	AuthHeader    string
	AuthCookieName string
	ProbeTimeout  time.Duration
	MaxBodySize   int64
}

func DefaultConfig() *Config {
	return &Config{
		AuthHeader:     "X-Request-ID",
		AuthCookieName: "session_token",
		ProbeTimeout:   10 * time.Second,
		MaxBodySize:    10 * 1024 * 1024,
	}
}

type CamouflageServer struct {
	*base.Module
	config *Config

	mu          sync.RWMutex
	listener    net.Listener
	httpServer  *http.Server
	proxy       *httputil.ReverseProxy
	tunnelConns chan net.Conn

	stopCh   chan struct{}
	stopOnce sync.Once

	totalRequests  uint64
	probeRequests  uint64
	tunnelRequests uint64
	blockedIPs     sync.Map
}

func New(cfg *Config) (*CamouflageServer, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	cs := &CamouflageServer{
		Module:      base.NewModule(ModuleName, ModuleVersion, nil),
		config:      cfg,
		tunnelConns: make(chan net.Conn, 256),
		stopCh:      make(chan struct{}),
	}

	if cfg.CoverSiteURL != "" {
		target, err := url.Parse(cfg.CoverSiteURL)
		if err != nil {
			return nil, err
		}
		cs.proxy = httputil.NewSingleHostReverseProxy(target)
		cs.proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			cs.serveDefaultPage(w)
		}
	}

	return cs, nil
}

func (cs *CamouflageServer) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	return cs.Module.Init(ctx, cfg)
}

func (cs *CamouflageServer) Start() error {
	if err := cs.Module.Start(); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", cs.handleRequest)

	cs.httpServer = &http.Server{
		Addr:              cs.config.ListenAddr,
		Handler:           mux,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
		ReadHeaderTimeout: 10 * time.Second,
	}

	var err error
	if cs.config.TLSCertFile != "" && cs.config.TLSKeyFile != "" {
		go func() {
			err = cs.httpServer.ListenAndServeTLS(cs.config.TLSCertFile, cs.config.TLSKeyFile)
			if err != nil && err != http.ErrServerClosed {
				log.Error("Camouflage TLS server error: %v", err)
			}
		}()
	} else if cs.config.ListenAddr != "" {
		go func() {
			err = cs.httpServer.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				log.Error("Camouflage server error: %v", err)
			}
		}()
	}

	cs.SetHealthy(true, "camouflage server active")
	log.Info("Camouflage server started on %s (cover: %s)", cs.config.ListenAddr, cs.config.CoverSiteURL)
	return nil
}

func (cs *CamouflageServer) Stop() error {
	cs.stopOnce.Do(func() { close(cs.stopCh) })
	if cs.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cs.httpServer.Shutdown(ctx)
	}
	return cs.Module.Stop()
}

func (cs *CamouflageServer) AcceptTunnel() (net.Conn, error) {
	conn, ok := <-cs.tunnelConns
	if !ok {
		return nil, io.EOF
	}
	return conn, nil
}

func (cs *CamouflageServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	atomic.AddUint64(&cs.totalRequests, 1)

	if cs.isAuthenticated(r) {
		atomic.AddUint64(&cs.tunnelRequests, 1)
		cs.handleTunnelUpgrade(w, r)
		return
	}

	atomic.AddUint64(&cs.probeRequests, 1)
	cs.serveCoverSite(w, r)
}

func (cs *CamouflageServer) isAuthenticated(r *http.Request) bool {
	if len(cs.config.AuthSecret) == 0 {
		return false
	}

	authVal := r.Header.Get(cs.config.AuthHeader)
	if authVal == "" {
		if cookie, err := r.Cookie(cs.config.AuthCookieName); err == nil {
			authVal = cookie.Value
		}
	}
	if authVal == "" {
		return false
	}

	if len(authVal) < 24 {
		return false
	}

	return cs.verifyAuthToken(authVal)
}

func (cs *CamouflageServer) verifyAuthToken(token string) bool {
	if len(token) < 24 {
		return false
	}

	tokenBytes := []byte(token)
	tsBytes := tokenBytes[:8]
	nonceBytes := tokenBytes[8:16]
	macBytes := tokenBytes[16:24]

	ts := binary.BigEndian.Uint64([]byte(padTo8(tsBytes)))
	now := uint64(time.Now().Unix())
	if ts > now+120 || now > ts+120 {
		return false
	}

	mac := hmac.New(sha256.New, cs.config.AuthSecret)
	mac.Write(tsBytes)
	mac.Write(nonceBytes)
	expected := mac.Sum(nil)[:8]

	return hmac.Equal(macBytes, expected)
}

func padTo8(b []byte) []byte {
	if len(b) >= 8 {
		return b[:8]
	}
	result := make([]byte, 8)
	copy(result[8-len(b):], b)
	return result
}

func (cs *CamouflageServer) handleTunnelUpgrade(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		cs.serveCoverSite(w, r)
		return
	}

	conn, _, err := hijacker.Hijack()
	if err != nil {
		cs.serveCoverSite(w, r)
		return
	}

	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	conn.Write([]byte(resp))

	select {
	case cs.tunnelConns <- conn:
	default:
		conn.Close()
	}
}

func (cs *CamouflageServer) serveCoverSite(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "nginx/1.24.0")
	w.Header().Set("X-Powered-By", "PHP/8.2")
	w.Header().Set("Vary", "Accept-Encoding")

	if cs.proxy != nil {
		cs.proxy.ServeHTTP(w, r)
		return
	}

	if cs.config.StaticDir != "" {
		http.FileServer(http.Dir(cs.config.StaticDir)).ServeHTTP(w, r)
		return
	}

	cs.serveDefaultPage(w)
}

func (cs *CamouflageServer) serveDefaultPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(200)
	w.Write(defaultPage)
}

func (cs *CamouflageServer) Stats() map[string]interface{} {
	return map[string]interface{}{
		"total_requests":  atomic.LoadUint64(&cs.totalRequests),
		"probe_requests":  atomic.LoadUint64(&cs.probeRequests),
		"tunnel_requests": atomic.LoadUint64(&cs.tunnelRequests),
	}
}

func GenerateAuthToken(secret []byte) string {
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().Unix()))

	nonce := make([]byte, 8)
	rand.Read(nonce)

	mac := hmac.New(sha256.New, secret)
	mac.Write(ts)
	mac.Write(nonce)
	sig := mac.Sum(nil)[:8]

	token := make([]byte, 24)
	copy(token[:8], ts)
	copy(token[8:16], nonce)
	copy(token[16:24], sig)

	return string(token)
}

var defaultPage = []byte(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Welcome</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;margin:0;background:#f5f5f5;color:#333}
.container{max-width:800px;margin:60px auto;padding:20px}
h1{font-size:2em;color:#2c3e50}
p{line-height:1.6;color:#555}
.footer{margin-top:40px;padding-top:20px;border-top:1px solid #ddd;font-size:0.85em;color:#999}
</style>
</head>
<body>
<div class="container">
<h1>Welcome to Our Service</h1>
<p>This server is currently under maintenance. We apologize for any inconvenience.</p>
<p>Please check back later for updates. If you need immediate assistance, please contact our support team.</p>
<div class="footer">
<p>&copy; 2024 All rights reserved. | Privacy Policy | Terms of Service</p>
</div>
</div>
</body>
</html>`)
