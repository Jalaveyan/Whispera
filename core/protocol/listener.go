package protocol

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	stdlog "log"
	mrand "math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	quicpkg "github.com/nekoskin/whispera/core/protocol/quic"

	quicgo "github.com/quic-go/quic-go"
	http3 "github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
)

func quicConnContext(ctx context.Context, c *quicgo.Conn) context.Context {
	return context.WithValue(ctx, quicpkg.ConnContextKey, c)
}

type noDelayListener struct {
	*net.TCPListener
}

type serverErrLogWriter struct{}

func (serverErrLogWriter) Write(p []byte) (int, error) {
	traceLog.Warnw("whispera_server_error", "msg", strings.TrimSpace(string(p)))
	return len(p), nil
}

func buildServerTLSConfig(cfg *ServerConfig) (*tls.Config, error) {
	cdnCipherSuites := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}
	cdnCurves := []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}

	if cfg.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("whispera: load cert: %w", err)
		}
		decoyCertDir := cfg.DecoyCertDir
		return &tls.Config{
			Certificates:           []tls.Certificate{cert},
			NextProtos:             []string{"h2", "http/1.1"},
			MinVersion:             tls.VersionTLS13,
			CipherSuites:           cdnCipherSuites,
			CurvePreferences:       cdnCurves,
			SessionTicketsDisabled: SpliceEnabled(),
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				return nil, nil
			},
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if hello.ServerName != "" {
					if c, ok := loadSNICert(decoyCertDir, hello.ServerName); ok {
						return c, nil
					}
				}
				return &cert, nil
			},
		}, nil
	}

	if cfg.Domain == "" {
		return nil, fmt.Errorf("whispera: neither TLSCert nor Domain configured")
	}

	cacheDir := cfg.ACMEDir
	if cacheDir == "" {
		cacheDir = "/var/lib/whispera/acme"
	}
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.Domain),
		Cache:      autocert.DirCache(cacheDir),
	}
	go func() { _ = http.ListenAndServe(":80", m.HTTPHandler(nil)) }()

	tlsCfg := m.TLSConfig()
	tlsCfg.NextProtos = []string{"h2", "http/1.1"}
	tlsCfg.MinVersion = tls.VersionTLS12
	tlsCfg.CipherSuites = cdnCipherSuites
	tlsCfg.CurvePreferences = cdnCurves
	tlsCfg.SessionTicketsDisabled = SpliceEnabled()
	domain := cfg.Domain
	origGet := tlsCfg.GetCertificate
	tlsCfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName == "" || hello.ServerName != domain {
			patched := *hello
			patched.ServerName = domain
			return origGet(&patched)
		}
		return origGet(hello)
	}
	return tlsCfg, nil
}

func startQUICServers(ctx context.Context, cfg *ServerConfig, mux *http.ServeMux, tlsCfg *tls.Config, camoKeys func() [][]byte, camoAddr func(sni string) string) (*http3.Server, []*http3.Server) {
	if cfg.QUICListenAddr == "" || cfg.TLSCert == "" {
		return nil, nil
	}
	_, port, _ := net.SplitHostPort(cfg.QUICListenAddr)
	if port == "" {
		port = "443"
	}
	cfg.altSvcHeader = fmt.Sprintf(`h3=":%s"; ma=2592000`, port)

	newServer := func() *http3.Server {
		return &http3.Server{
			Handler:     mux,
			TLSConfig:   http3.ConfigureTLSConfig(tlsCfg.Clone()),
			QUICConfig:  chromeLikeQUICConfig(),
			ConnContext: quicConnContext,
		}
	}
	serve := func(srv *http3.Server, addr string) {
		pconn, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", addr)
		if err != nil {
			return
		}
		camoConn := quicpkg.NewCamoConn(pconn, camoKeys, camoAddr, decoyIPRateAllow)
		go func() { _ = srv.Serve(camoConn) }()
	}

	h3srv := newServer()
	serve(h3srv, cfg.QUICListenAddr)

	var extra []*http3.Server
	for _, addr := range cfg.ExtraQUICListenAddrs {
		s := newServer()
		extra = append(extra, s)
		serve(s, addr)
	}
	return h3srv, extra
}

func serveBackendH2C(ctx context.Context, cfg *ServerConfig, mux *http.ServeMux) error {
	backendLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.BackendH2CAddr)
	if err != nil {
		return fmt.Errorf("whispera: backend h2c listen: %w", err)
	}
	defer backendLn.Close()
	go func() {
		<-ctx.Done()
		backendLn.Close()
	}()

	h2s := &http2.Server{
		MaxUploadBufferPerConnection: 1 << 28,
		MaxUploadBufferPerStream:     1 << 26,
	}
	opts := &http2.ServeConnOpts{
		Handler:    mux,
		BaseConfig: &http.Server{ErrorLog: stdlog.New(serverErrLogWriter{}, "", 0)},
	}
	for {
		conn, err := backendLn.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				continue
			}
		}
		go func(c net.Conn) {
			traceLog.Infow("whispera_conn_state", "remote", c.RemoteAddr().String(), "state", "active")
			h2s.ServeConn(c, opts)
			traceLog.Infow("whispera_conn_state", "remote", c.RemoteAddr().String(), "state", "closed")
		}(conn)
	}
}

func ListenAndServe(ctx context.Context, cfg *ServerConfig) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, cfg)
	})

	go func() {
		ticker := time.NewTicker(replayWindowSeconds * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cfg.seenTokens.sweep(time.Now().Unix())
			}
		}
	}()

	if cfg.BackendH2CAddr != "" {
		return serveBackendH2C(ctx, cfg, mux)
	}

	listenAddr := cfg.ListenAddr
	if listenAddr == "" {
		listenAddr = ":443"
	}

	tlsCfg, err := buildServerTLSConfig(cfg)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:      listenAddr,
		Handler:   mux,
		TLSConfig: tlsCfg,
		ErrorLog:  stdlog.New(serverErrLogWriter{}, "", 0),
		ConnState: func(c net.Conn, state http.ConnState) {
			traceLog.Infow("whispera_conn_state", "remote", c.RemoteAddr().String(), "state", state.String())
		},
	}

	if err := http2.ConfigureServer(srv, &http2.Server{
		MaxUploadBufferPerConnection: 1 << 28,
		MaxUploadBufferPerStream:     1 << 26,
	}); err != nil {
		return fmt.Errorf("whispera: h2 server config: %w", err)
	}

	if cfg.DecoyOrigin != "" {
		cfg.proxy = newDecoyProxy(cfg.DecoyOrigin)
	}

	camoKeys := camoKeysFunc(cfg)
	if len(camoKeys()) == 0 {
		traceLog.Errorw("camo_gate_no_keys",
			"hint", "no registered users with a 32-byte PSK; every TLS connection is relayed to the decoy — register a user and check /etc/whispera/users.json is readable by the service user")
	}
	camoAddr := camoDecoyAddr(cfg.DecoyOrigin)

	h3srv, extraH3srvs := startQUICServers(ctx, cfg, mux, tlsCfg, camoKeys, camoAddr)

	go func() {
		<-ctx.Done()
		if h3srv != nil {
			h3srv.Close()
		}
		for _, extraH3srv := range extraH3srvs {
			extraH3srv.Close()
		}
		srv.Close()
	}()

	for _, extraAddr := range cfg.ExtraListenAddrs {
		extraLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", extraAddr)
		if err != nil {
			continue
		}
		extraBase := &noDelayListener{TCPListener: extraLn.(*net.TCPListener)}
		var extraTLSLn net.Listener = tls.NewListener(newCamouflageListener(extraBase, camoKeys, camoAddr), tlsCfg)
		if perflowEnabled() {
			extraTLSLn = newPerflowMux(extraTLSLn, cfg)
		}
		go srv.Serve(extraTLSLn)
	}

	rawLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("whispera: listen: %w", err)
	}
	baseLn := &noDelayListener{TCPListener: rawLn.(*net.TCPListener)}
	var tlsLn net.Listener = tls.NewListener(newCamouflageListener(baseLn, camoKeys, camoAddr), tlsCfg)
	if perflowEnabled() {
		tlsLn = newPerflowMux(tlsLn, cfg)
	}
	return srv.Serve(tlsLn)
}

func (l *noDelayListener) Accept() (net.Conn, error) {
	tc, err := l.TCPListener.AcceptTCP()
	if err != nil {
		return nil, err
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(time.Duration(30+mrand.Intn(61)) * time.Second)
	tc.SetNoDelay(true)
	return tc, nil
}

type perflowMux struct {
	net.Listener
	cfg    *ServerConfig
	httpCh chan net.Conn
	closed chan struct{}
	err    error
}

func newPerflowMux(ln net.Listener, cfg *ServerConfig) *perflowMux {
	m := &perflowMux{
		Listener: ln,
		cfg:      cfg,
		httpCh:   make(chan net.Conn),
		closed:   make(chan struct{}),
	}
	go m.run()
	return m
}

func (m *perflowMux) run() {
	for {
		c, err := m.Listener.Accept()
		if err != nil {
			m.err = err
			close(m.httpCh)
			return
		}
		go m.classify(c)
	}
}

func (m *perflowMux) classify(c net.Conn) {
	c.SetReadDeadline(time.Now().Add(perflowPreambleTimeout))
	var first [1]byte
	if _, err := io.ReadFull(c, first[:]); err != nil {
		c.Close()
		return
	}
	if first[0] == perflowMagic {
		handlePerflowConn(c, m.cfg)
		return
	}
	c.SetReadDeadline(time.Time{})
	pc := &prefixConn{Conn: c, prefix: []byte{first[0]}}
	select {
	case m.httpCh <- pc:
	case <-m.closed:
		c.Close()
	}
}

func (m *perflowMux) Accept() (net.Conn, error) {
	select {
	case c, ok := <-m.httpCh:
		if !ok {
			if m.err != nil {
				return nil, m.err
			}
			return nil, net.ErrClosed
		}
		return c, nil
	case <-m.closed:
		return nil, net.ErrClosed
	}
}

func (m *perflowMux) Close() error {
	select {
	case <-m.closed:
	default:
		close(m.closed)
	}
	return m.Listener.Close()
}

func handlePerflowConn(c net.Conn, cfg *ServerConfig) {
	c.SetReadDeadline(time.Now().Add(perflowPreambleTimeout))
	sessionID := make([]byte, 16)
	if _, err := io.ReadFull(c, sessionID); err != nil {
		c.Close()
		return
	}
	var tl [2]byte
	if _, err := io.ReadFull(c, tl[:]); err != nil {
		c.Close()
		return
	}
	tokLen := binary.BigEndian.Uint16(tl[:])
	if tokLen == 0 || tokLen > 512 {
		c.Close()
		return
	}
	tok := make([]byte, tokLen)
	if _, err := io.ReadFull(c, tok); err != nil {
		c.Close()
		return
	}
	c.SetReadDeadline(time.Time{})

	secret, userID := resolveSecret(cfg, string(tok), sessionID)
	if secret == nil {
		c.Close()
		return
	}
	if !cfg.consumeToken(string(tok)) {
		c.Close()
		return
	}
	if cfg.OnConn == nil {
		c.Close()
		return
	}
	cfg.OnConn(c, userID, secret)
}

func handleRequest(w http.ResponseWriter, r *http.Request, cfg *ServerConfig) {
	if r.Method == http.MethodPost && registerRTDatagrams(w, r, cfg) {
		return
	}
	serveDecoy(w, r, cfg)
}

func registerRTDatagrams(w http.ResponseWriter, r *http.Request, cfg *ServerConfig) bool {
	tokenHdr := r.Header.Get(rtDatagramTokenHeader)
	if len(tokenHdr) < 8 || tokenHdr[:7] != "Bearer " {
		return false
	}

	quicConn, ok := r.Context().Value(quicpkg.ConnContextKey).(*quicgo.Conn)
	if !ok {
		traceLog.Infow("rt_datagram_decoy_fallback", "reason", "not_a_quic_request", "remote", r.RemoteAddr, "proto", r.Proto)
		return false
	}
	sessionID, err := hex.DecodeString(r.Header.Get(rtDatagramSessionHeader))
	if err != nil || len(sessionID) == 0 {
		return false
	}

	token := tokenHdr[7:]
	secret, userID := resolveSecret(cfg, token, sessionID)
	if secret == nil {
		traceLog.Infow("rt_datagram_decoy_fallback", "reason", "secret_not_resolved", "remote", r.RemoteAddr)
		return false
	}
	if !cfg.consumeToken(token) {
		traceLog.Infow("rt_datagram_decoy_fallback", "reason", "token_replay_or_expired", "remote", r.RemoteAddr, "user", userID)
		return false
	}

	quicpkg.RegisterDatagramConn(sessionID, quicConn)
	traceLog.Infow("rt_datagram_registered", "user", userID, "remote", r.RemoteAddr)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	<-r.Context().Done()
	return true
}

func resolveSecret(cfg *ServerConfig, token string, sessionID []byte) ([]byte, string) {
	if len(cfg.SharedSecret) == 32 {
		k := DeriveKeys(cfg.SharedSecret)
		if VerifyAuthToken(k.Auth, token, sessionID) {
			return cfg.SharedSecret, "default"
		}
	}
	if cfg.GetUsers == nil {
		return nil, ""
	}
	for _, u := range cfg.GetUsers() {
		if len(u.PSK) != 32 {
			continue
		}
		k := DeriveKeys(u.PSK)
		if VerifyAuthToken(k.Auth, token, sessionID) {
			return u.PSK, u.UserID
		}
	}
	probeClockDriftOnFailure(cfg, token, sessionID)
	return nil, ""
}

func probeClockDriftOnFailure(cfg *ServerConfig, token string, sessionID []byte) {
	if len(cfg.SharedSecret) == 32 {
		k := DeriveKeys(cfg.SharedSecret)
		if drift, found := ProbeClockDrift(k.Auth, token, sessionID); found {
			traceLog.Warnw("whispera_auth_clock_drift_suspected", "user", "default", "drift_windows", drift, "drift_seconds", drift*authWindowSeconds)
			return
		}
	}
	if cfg.GetUsers == nil {
		return
	}
	for _, u := range cfg.GetUsers() {
		if len(u.PSK) != 32 {
			continue
		}
		k := DeriveKeys(u.PSK)
		if drift, found := ProbeClockDrift(k.Auth, token, sessionID); found {
			traceLog.Warnw("whispera_auth_clock_drift_suspected", "user", u.UserID, "drift_windows", drift, "drift_seconds", drift*authWindowSeconds)
			return
		}
	}
}
