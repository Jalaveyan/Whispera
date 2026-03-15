package proxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

type HTTPProxy struct {
	config      *Config
	server      *http.Server
	authHandler AuthHandler
	stats       *Stats
	listener    net.Listener
}

func NewHTTPProxy(config *Config) *HTTPProxy {
	return &HTTPProxy{
		config: config,
		stats: &Stats{
			StartTime: time.Now(),
		},
	}
}

func (p *HTTPProxy) SetAuthHandler(handler AuthHandler) {
	p.authHandler = handler
}
func (p *HTTPProxy) Type() ProxyType {
	return ProxyHTTP
}
func (p *HTTPProxy) Start(ctx context.Context) error {
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", p.config.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", p.config.Addr, err)
	}
	p.listener = listener

	p.server = &http.Server{
		Addr:         p.config.Addr,
		Handler:      http.HandlerFunc(p.handleRequest),
		ReadTimeout:  p.config.Timeout,
		WriteTimeout: p.config.Timeout,
		IdleTimeout:  p.config.IdleTimeout,
	}

	log.Printf("[HTTP-PROXY] ✅ Server listening on %s", p.config.Addr)

	go func() {
		if err := p.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("[HTTP-PROXY] ❌ Server error: %v", err)
		}
	}()

	<-ctx.Done()
	return p.Stop()
}
func (p *HTTPProxy) Stop() error {
	if p.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return p.server.Shutdown(ctx)
	}
	return nil
}

func (p *HTTPProxy) Addr() net.Addr {
	if p.listener != nil {
		return p.listener.Addr()
	}
	return nil
}

func (p *HTTPProxy) Stats() *Stats {
	return p.stats
}
func (p *HTTPProxy) Reset() {
	p.stats = &Stats{
		StartTime: time.Now(),
	}
}

func (p *HTTPProxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	p.stats.Connections++

	if p.authHandler != nil && !p.checkAuth(r) {
		p.stats.Errors++
		p.sendAuthRequired(w)
		return
	}

	switch r.Method {
	case http.MethodConnect:
		p.handleHTTPS(w, r)
	default:
		p.handleHTTP(w, r)
	}
}

func (p *HTTPProxy) checkAuth(r *http.Request) bool {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return false
	}

	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || parts[0] != "Basic" {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		return false
	}

	return p.authHandler.Authenticate(credentials[0], credentials[1])
}

func (p *HTTPProxy) sendAuthRequired(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", "Basic realm=\"Whispera Proxy\"")
	w.WriteHeader(http.StatusProxyAuthRequired)
}

func (p *HTTPProxy) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	dstConn, err := (&net.Dialer{Timeout: p.config.Timeout}).DialContext(r.Context(), "tcp", r.Host)
	if err != nil {
		p.stats.Errors++
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer dstConn.Close()

	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.stats.Errors++
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		p.stats.Errors++
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	p.proxyData(clientConn, dstConn)
}

func (p *HTTPProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	r.RequestURI = ""
	r.URL.Host = r.Host
	r.URL.Scheme = "http"

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: p.config.Timeout}).DialContext(ctx, network, addr)
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   p.config.Timeout,
	}

	resp, err := client.Do(r)
	if err != nil {
		p.stats.Errors++
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)

	io.Copy(w, resp.Body)
}

func (p *HTTPProxy) proxyData(client, server net.Conn) {
	done := make(chan struct{}, 2)

	bufSize := 256 * 1024

	go func() {
		defer client.Close()
		defer server.Close()

		buf := make([]byte, bufSize)
		io.CopyBuffer(server, client, buf)
		done <- struct{}{}
	}()

	go func() {
		defer client.Close()
		defer server.Close()
		buf := make([]byte, bufSize)
		io.CopyBuffer(client, server, buf)
		done <- struct{}{}
	}()

	<-done
}
