package protocol

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
)

type decoyProxy struct {
	origin string
	rp     *httputil.ReverseProxy
}

const jitterCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomJitter(minLen, maxLen int) string {
	n := minLen + mrand.Intn(maxLen-minLen+1)
	b := make([]byte, n)
	for i := range b {
		b[i] = jitterCharset[mrand.Intn(len(jitterCharset))]
	}
	return string(b)
}

func serveDecoy(w http.ResponseWriter, r *http.Request, cfg *ServerConfig) {
	if cfg != nil && cfg.proxy != nil {
		cfg.proxy.serve(w, r)
		return
	}
	w.Header().Set("Server", "nginx/1.24.0")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if cfg != nil && cfg.altSvcHeader != "" {
		w.Header().Set("Alt-Svc", cfg.altSvcHeader)
	}

	path := r.URL.Path
	var ct, body string
	switch {
	case strings.HasSuffix(path, ".js"):
		ct = "application/javascript; charset=utf-8"
		body = "(function(){'use strict';/*" + randomJitter(8, 220) + "*/})();\n"
		w.Header().Set("Cache-Control", "public, max-age=31536000")
	case strings.HasSuffix(path, ".css"):
		ct = "text/css; charset=utf-8"
		body = "*{box-sizing:border-box}body{margin:0}/*" + randomJitter(8, 220) + "*/\n"
		w.Header().Set("Cache-Control", "public, max-age=31536000")
	case strings.HasSuffix(path, ".json") ||
		strings.HasSuffix(path, "health") ||
		strings.HasSuffix(path, "config"):
		ct = "application/json; charset=utf-8"
		body = `{"status":"ok","version":"1.0.0","_t":"` + randomJitter(4, 96) + `"}` + "\n"
		w.Header().Set("Cache-Control", "no-cache")
	case strings.HasSuffix(path, ".png") ||
		strings.HasSuffix(path, ".ico") ||
		strings.HasSuffix(path, ".woff2"):
		switch {
		case strings.HasSuffix(path, ".ico"):
			ct = "image/x-icon"
		case strings.HasSuffix(path, ".png"):
			ct = "image/png"
		case strings.HasSuffix(path, ".woff2"):
			ct = "font/woff2"
		}
		body = randomJitter(180, 4096)
		w.Header().Set("Cache-Control", "public, max-age=86400")
	case path == "/robots.txt":
		ct = "text/plain; charset=utf-8"
		body = "User-agent: *\nDisallow: /api/\n# " + randomJitter(4, 96) + "\n"
		w.Header().Set("Cache-Control", "public, max-age=86400")
	case path == "/manifest.json":
		ct = "application/json; charset=utf-8"
		body = `{"name":"","short_name":"","start_url":"/","display":"standalone","icons":[],"_t":"` + randomJitter(4, 96) + `"}` + "\n"
		w.Header().Set("Cache-Control", "public, max-age=3600")
	default:
		ct = "text/html; charset=utf-8"
		body = "<!DOCTYPE html><html><head><title></title></head><body><!--" + randomJitter(16, 600) + "--></body></html>\n"
		w.Header().Set("Cache-Control", "max-age=3600")
	}

	w.Header().Set("Content-Type", ct)
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	if body != "" {
		io.WriteString(w, body)
	}
}

type DecoyGate struct {
	mu      sync.Mutex
	cond    *sync.Cond
	open    int64
	navEdge chan struct{}
	closed  atomic.Bool
	started atomic.Bool
}

func NewDecoyGate() *DecoyGate {
	g := &DecoyGate{navEdge: make(chan struct{}, 1)}
	g.cond = sync.NewCond(&g.mu)
	return g
}

func (g *DecoyGate) Enter() {
	g.mu.Lock()
	if g.open == 0 {
		select {
		case g.navEdge <- struct{}{}:
		default:
		}
	}
	g.open++
	g.mu.Unlock()
}

func (g *DecoyGate) Leave() {
	g.mu.Lock()
	if g.open > 0 {
		g.open--
	}
	if g.open == 0 {
		g.cond.Broadcast()
	}
	g.mu.Unlock()
}

func (g *DecoyGate) Close() {
	g.closed.Store(true)
	g.mu.Lock()
	g.cond.Broadcast()
	g.mu.Unlock()
}

func (g *DecoyGate) waitIdle() {
	g.mu.Lock()
	for g.open > 0 && !g.closed.Load() {
		g.cond.Wait()
	}
	g.mu.Unlock()
}

func (g *DecoyGate) idle() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.open == 0
}

type decoyDriver struct {
	gate       *DecoyGate
	client     *http.Client
	prof       browserProfile
	origin     string
	serverAddr string
	sni        string
}

func idleBeacon() time.Duration {
	return time.Duration(45000+mrand.Intn(45001)) * time.Millisecond
}

func pickPath(s []string) string { return s[mrand.Intn(len(s))] }

func (d *decoyDriver) get(ctx context.Context, path string) {
	d.gate.waitIdle()
	if ctx.Err() != nil {
		return
	}
	reqCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
		fmt.Sprintf("https://%s%s", d.serverAddr, path), nil)
	if err != nil {
		return
	}
	req.Host = d.sni
	d.prof.apply(req, d.origin)
	if resp, err := d.client.Do(req); err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func (d *decoyDriver) parallelGet(ctx context.Context, paths []string, n int) {
	if n > len(paths) {
		n = len(paths)
	}
	if n <= 0 {
		return
	}
	chosen := mrand.Perm(len(paths))[:n]
	var wg sync.WaitGroup
	for _, i := range chosen {
		wg.Add(1)
		p := paths[i]
		go func() { defer wg.Done(); d.get(ctx, p) }()
		time.Sleep(time.Duration(mrand.Intn(20)) * time.Millisecond)
	}
	wg.Wait()
}

func (d *decoyDriver) emitPageLoad(ctx context.Context) {
	d.get(ctx, pickPath(decoyGraph[0]))
	d.parallelGet(ctx, decoyGraph[1], 2+mrand.Intn(4))
	d.parallelGet(ctx, decoyGraph[2], 1+mrand.Intn(2))
	d.get(ctx, pickPath(decoyGraph[3]))
}

func (d *decoyDriver) run(ctx context.Context) {
	beacon := time.NewTimer(idleBeacon())
	defer beacon.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.gate.navEdge:
			d.emitPageLoad(ctx)
		case <-beacon.C:
			if d.gate.idle() {
				d.get(ctx, pickPath(decoyGraph[3]))
			}
			beacon.Reset(idleBeacon())
		}
	}
}

func newDecoyClient(cfg *ClientConfig) (*http.Client, browserProfile, string, string, func()) {
	sni := sessionSNI(cfg)
	helloID, helloRaw, uaID := sessionFingerprint()
	prof := newBrowserProfile(uaID)

	var dialedMu sync.Mutex
	var dialed []net.Conn

	dial := func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		var rawConn net.Conn
		var err error
		if cfg.TCPDialer != nil {
			rawConn, err = cfg.TCPDialer(ctx, network, addr)
		} else {
			d := &net.Dialer{Timeout: dialTimeout}
			rawConn, err = d.DialContext(ctx, network, addr)
		}
		if err != nil {
			return nil, err
		}
		if tcpConn, ok := rawConn.(*net.TCPConn); ok {
			tcpConn.SetNoDelay(true)
		}
		uCfg := &utls.Config{ServerName: sni, InsecureSkipVerify: true, PreferSkipResumptionOnNilExtension: true}
		if cfg.ServerCertPin != "" || cfg.ServerIDPub != "" {
			uCfg.VerifyPeerCertificate = certVerifier(cfg.ServerCertPin, cfg.ServerIDPub, sni)
		}
		if sc, ok := cfg.SessionCache.(utls.ClientSessionCache); ok {
			uCfg.ClientSessionCache = sc
		}
		var uConn *utls.UConn
		if len(helloRaw) > 0 {
			spec, err := specFromRaw(helloRaw)
			if err != nil {
				rawConn.Close()
				return nil, err
			}
			uConn = utls.UClient(rawConn, uCfg, utls.HelloCustom)
			if err := uConn.ApplyPreset(spec); err != nil {
				rawConn.Close()
				return nil, err
			}
		} else {
			uConn = utls.UClient(rawConn, uCfg, helloID)
		}
		if err := uConn.BuildHandshakeState(); err != nil {
			rawConn.Close()
			return nil, err
		}
		if err := uConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, err
		}
		dialedMu.Lock()
		dialed = append(dialed, uConn)
		dialedMu.Unlock()
		return uConn, nil
	}

	t := newH2Transport(dial)
	client := &http.Client{
		Transport:     t,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	cleanup := func() {
		t.CloseIdleConnections()
		dialedMu.Lock()
		conns := dialed
		dialed = nil
		dialedMu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	}
	return client, prof, "https://" + sni, sni, cleanup
}

func StartDecoy(ctx context.Context, gate *DecoyGate, cfg *ClientConfig) {
	if gate == nil || !gate.started.CompareAndSwap(false, true) {
		return
	}
	client, prof, origin, sni, cleanup := newDecoyClient(cfg)
	d := &decoyDriver{
		gate:       gate,
		client:     client,
		prof:       prof,
		origin:     origin,
		serverAddr: cfg.ServerAddr,
		sni:        sni,
	}
	go func() {
		<-ctx.Done()
		gate.Close()
		cleanup()
	}()
	go d.run(ctx)
}

func newDecoyProxy(origin string) *decoyProxy {
	origin = strings.TrimRight(origin, "/")
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return &decoyProxy{origin: origin}
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		serveDecoy(w, r, nil)
	}
	return &decoyProxy{origin: origin, rp: rp}
}

func (p *decoyProxy) serve(w http.ResponseWriter, r *http.Request) {
	if p.rp == nil {
		serveDecoy(w, r, nil)
		return
	}
	p.rp.ServeHTTP(w, r)
}
