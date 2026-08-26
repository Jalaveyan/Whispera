package protocol

import (
	"io"
	mrand "math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
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
