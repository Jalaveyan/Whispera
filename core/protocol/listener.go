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
	"runtime/debug"
	"strings"
	"sync/atomic"
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

func newACMEManager(cfg *ServerConfig) *autocert.Manager {
	cacheDir := cfg.ACMEDir
	if cacheDir == "" {
		cacheDir = "/var/lib/whispera/acme"
	}
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.Domain),
		Cache:      autocert.DirCache(cacheDir),
	}
	go func() {
		if err := http.ListenAndServe(":80", m.HTTPHandler(nil)); err != nil {
			traceLog.Errorw("acme_http_listener_failed", "err", err.Error(),
				"hint", "port 80 is needed for the http-01 challenge; certificate renewal will fail")
		}
	}()
	return m
}

var cdnCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

var cdnCurves = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}

func sniCertResolver(cfg *ServerConfig, static *tls.Certificate) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	decoyCertDir, domain := cfg.DecoyCertDir, cfg.Domain

	var acmeGet func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	if domain != "" {
		acmeGet = newACMEManager(cfg).GetCertificate
	}

	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName != "" {
			if acmeGet != nil && hello.ServerName == domain {
				return acmeGet(hello)
			}
			if c, ok := loadSNICert(decoyCertDir, hello.ServerName); ok {
				return c, nil
			}
		}
		if acmeGet != nil {
			patched := *hello
			patched.ServerName = domain
			return acmeGet(&patched)
		}
		return static, nil
	}
}

func staticCertTLSConfig(cfg *ServerConfig) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("whispera: load cert: %w", err)
	}
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
		GetCertificate: sniCertResolver(cfg, &cert),
	}, nil
}

func acmeTLSConfig(cfg *ServerConfig) *tls.Config {
	tlsCfg := newACMEManager(cfg).TLSConfig()
	tlsCfg.NextProtos = []string{"h2", "http/1.1"}
	tlsCfg.MinVersion = tls.VersionTLS12
	tlsCfg.CipherSuites = cdnCipherSuites
	tlsCfg.CurvePreferences = cdnCurves
	tlsCfg.SessionTicketsDisabled = SpliceEnabled()

	domain := cfg.Domain
	origGet := tlsCfg.GetCertificate
	tlsCfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName == domain {
			return origGet(hello)
		}
		patched := *hello
		patched.ServerName = domain
		return origGet(&patched)
	}
	return tlsCfg
}

func buildServerTLSConfig(cfg *ServerConfig) (*tls.Config, error) {
	if cfg.TLSCert != "" {
		return staticCertTLSConfig(cfg)
	}
	if cfg.Domain == "" {
		return nil, fmt.Errorf("whispera: neither TLSCert nor Domain configured")
	}
	return acmeTLSConfig(cfg), nil
}

func startQUICServers(ctx context.Context, cfg *ServerConfig, mux *http.ServeMux, tlsCfg *tls.Config, camoKeys func() [][]byte, camoAddr func(sni string) string) (*http3.Server, []*http3.Server) {
	if cfg.QUICListenAddr == "" || cfg.TLSCert == "" {
		return nil, nil
	}
	host, port, _ := net.SplitHostPort(cfg.QUICListenAddr)
	if port == "" {
		port = "443"
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		traceLog.Errorw("quic_listen_loopback_only", "addr", cfg.QUICListenAddr,
			"hint", "no client can reach this address, so the datagram lane never comes up and all UDP rides the TCP tunnel; bind 0.0.0.0 or the public address, ideally on the same port as TCP")
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
			traceLog.Errorw("quic_listen_failed", "addr", addr, "err", err.Error(),
				"hint", "the datagram lane is down; clients fall back to TCP only")
			return
		}
		camoConn := quicpkg.NewCamoConn(pconn, camoKeys, quicSelector(cfg), camoAddr, decoyIPRateAllow)
		go func() {
			if err := srv.Serve(camoConn); err != nil && ctx.Err() == nil {
				traceLog.Errorw("quic_serve_stopped", "addr", addr, "err", err.Error())
			}
		}()
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

func sweepSeenTokens(ctx context.Context, cfg *ServerConfig) {
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
}

func newWhisperaHTTPServer(listenAddr string, mux http.Handler, tlsCfg *tls.Config) (*http.Server, error) {
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
		return nil, fmt.Errorf("whispera: h2 server config: %w", err)
	}
	return srv, nil
}

func quicSelector(cfg *ServerConfig) func(random, keyShare []byte) bool {
	return func(random, keyShare []byte) bool {
		_, ok := resolveBySelector(cfg, random, keyShare)
		return ok
	}
}

func camoTLSListener(base net.Listener, cfg *ServerConfig, tlsCfg *tls.Config, camoKeys func() [][]byte, camoAddr func(string) string) net.Listener {
	bySelector := func(random, keyShare []byte) (string, []byte, bool) {
		entry, ok := resolveBySelector(cfg, random, keyShare)
		return entry.userID, entry.psk, ok
	}
	ln := tls.NewListener(newCamouflageListener(base, camoKeys, bySelector, camoAddr), tlsCfg)
	if perflowEnabled() {
		return newPerflowMux(ln, cfg)
	}
	return ln
}

func serveExtraListeners(ctx context.Context, cfg *ServerConfig, srv *http.Server, tlsCfg *tls.Config, camoKeys func() [][]byte, camoAddr func(string) string) {
	for _, extraAddr := range cfg.ExtraListenAddrs {
		extraLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", extraAddr)
		if err != nil {
			traceLog.Warnw("whispera_extra_listen_failed", "addr", extraAddr, "err", err.Error())
			continue
		}
		base := &noDelayListener{TCPListener: extraLn.(*net.TCPListener)}
		go srv.Serve(camoTLSListener(base, cfg, tlsCfg, camoKeys, camoAddr))
	}
}

func ListenAndServe(ctx context.Context, cfg *ServerConfig) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, cfg)
	})
	go sweepSeenTokens(ctx, cfg)

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
	srv, err := newWhisperaHTTPServer(listenAddr, mux, tlsCfg)
	if err != nil {
		return err
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

	serveExtraListeners(ctx, cfg, srv, tlsCfg, camoKeys, camoAddr)

	rawLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("whispera: listen: %w", err)
	}
	base := &noDelayListener{TCPListener: rawLn.(*net.TCPListener)}
	return srv.Serve(camoTLSListener(base, cfg, tlsCfg, camoKeys, camoAddr))
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
	defer func() {
		if r := recover(); r != nil {
			traceLog.Errorw("perflow_classify_panic", "remote", c.RemoteAddr().String(), "err", fmt.Sprint(r), "stack", string(debug.Stack()))
			c.Close()
		}
	}()
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
	remote := c.RemoteAddr().String()
	reject := func(reason string, err error) {
		traceLog.Infow("perflow_preamble_rejected", "remote", remote, "reason", reason, "err", err)
		c.Close()
	}

	c.SetReadDeadline(time.Now().Add(perflowPreambleTimeout))
	sessionID := make([]byte, 16)
	if _, err := io.ReadFull(c, sessionID); err != nil {
		reject("session_id", err)
		return
	}
	var tl [2]byte
	if _, err := io.ReadFull(c, tl[:]); err != nil {
		reject("token_length", err)
		return
	}
	tokLen := binary.BigEndian.Uint16(tl[:])
	if tokLen == 0 || tokLen > 512 {
		reject("token_length_out_of_range", fmt.Errorf("%d", tokLen))
		return
	}
	tok := make([]byte, tokLen)
	if _, err := io.ReadFull(c, tok); err != nil {
		reject("token", err)
		return
	}
	c.SetReadDeadline(time.Time{})

	secret, userID := resolveSecretFor(cfg, knownUserOf(c), string(tok), sessionID)
	if secret == nil {
		reject("unknown_token", nil)
		return
	}
	if !cfg.consumeToken(string(tok)) {
		reject("token_replayed", nil)
		return
	}
	if cfg.OnConn == nil {
		reject("no_conn_handler", nil)
		return
	}
	cfg.OnConn(AcceptedConn{Conn: c, UserID: userID, SessionID: sessionID, Secret: secret})
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

var lastDriftProbe atomic.Int64

const driftProbeInterval = 60

func probeClockDriftOnFailure(cfg *ServerConfig, token string, sessionID []byte) {
	now := time.Now().Unix()
	prev := lastDriftProbe.Load()
	if now-prev < driftProbeInterval || !lastDriftProbe.CompareAndSwap(prev, now) {
		return
	}
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
