package proxy

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"whispera/internal/logger"
)

type HTTPServer struct {
	listenAddr  string
	handler     func(*http.Request, http.ResponseWriter) error
	authHandler func(username, password string) bool
	log         *logger.Logger
}

func NewHTTPServer(addr string, handler func(*http.Request, http.ResponseWriter) error) *HTTPServer {
	return &HTTPServer{
		listenAddr: addr,
		handler:    handler,
		log:        logger.Module("http-proxy"),
	}
}

func (s *HTTPServer) SetAuthHandler(handler func(username, password string) bool) {
	s.authHandler = handler
}

func (s *HTTPServer) ListenAndServe() error {
	httpServer := &http.Server{
		Addr:         s.listenAddr,
		Handler:      http.HandlerFunc(s.handleRequest),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	s.log.Info("✅ Server listening on %s - ready to accept connections", s.listenAddr)
	return httpServer.ListenAndServe()
}

func (s *HTTPServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	if s.authHandler != nil {
		if !s.checkAuth(r) {
			w.Header().Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
	}

	if r.Method == http.MethodConnect {
		s.handleCONNECT(w, r)
		return
	}

	if err := s.handler(r, w); err != nil {
		s.log.Error("Handler error: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
	}
}

func (s *HTTPServer) checkAuth(r *http.Request) bool {
	if s.authHandler == nil {
		return true
	}

	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return false
	}

	if !strings.HasPrefix(auth, "Basic ") {
		return false
	}

	encoded := auth[6:]
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return false
	}

	return s.authHandler(parts[0], parts[1])
}

func (s *HTTPServer) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	targetAddr := r.Host
	if targetAddr == "" {
		targetAddr = r.URL.Host
	}

	targetConn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(r.Context(), "tcp", targetAddr)
	if err != nil {
		s.log.Error("Failed to connect to %s: %v", targetAddr, err)
		http.Error(w, "Failed to connect to target", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Failed to hijack connection", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	response := "HTTP/1.1 200 Connection Established\r\n\r\n"
	if _, err := clientConn.Write([]byte(response)); err != nil {
		s.log.Error("Failed to send response: %v", err)
		return
	}

	go func() {
		io.Copy(targetConn, clientConn)
		targetConn.Close()
	}()
	io.Copy(clientConn, targetConn)
}

func HandleHTTPRequest(r *http.Request, w http.ResponseWriter, targetURL string) error {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}

	targetReq := r.Clone(r.Context())
	targetReq.URL = parsedURL
	targetReq.Host = parsedURL.Host
	targetReq.RequestURI = ""

	targetReq.Header.Del("Proxy-Connection")
	targetReq.Header.Del("Proxy-Authorization")
	targetReq.Header.Del("Connection")

	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
	}

	resp, err := client.Do(targetReq)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)

	_, err = io.Copy(w, resp.Body)
	return err
}

func SimpleHTTPProxyHandler() func(*http.Request, http.ResponseWriter) error {
	return func(r *http.Request, w http.ResponseWriter) error {
		targetURL := r.URL.String()
		if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
			targetURL = "http://" + r.Host + targetURL
		}

		return HandleHTTPRequest(r, w, targetURL)
	}
}

func ForwardHTTPProxyHandler(proxyURL string) func(*http.Request, http.ResponseWriter) error {
	return func(r *http.Request, w http.ResponseWriter) error {
		return HandleHTTPRequest(r, w, proxyURL)
	}
}
