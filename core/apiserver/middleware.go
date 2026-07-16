package apiserver

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"github.com/nekoskin/whispera/app/auth"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"
)

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		allowedOrigin := ""
		if len(s.config.AllowedOrigins) > 0 {
			for _, allowed := range s.config.AllowedOrigins {
				if allowed == origin || allowed == "*" {
					allowedOrigin = origin
					break
				}
			}
		} else {
			if origin != "" {
				originHost := origin
				if i := strings.Index(originHost, "://"); i >= 0 {
					originHost = originHost[i+3:]
				}
				originHost = strings.TrimRight(originHost, "/")
				reqHost := r.Host
				if h, _, err := net.SplitHostPort(reqHost); err == nil {
					reqHost = h
				}
				if h, _, err := net.SplitHostPort(originHost); err == nil {
					originHost = h
				}
				if originHost == reqHost {
					allowedOrigin = origin
				}
			}
		}

		if allowedOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Max-Age", "3600")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-XSS-Protection", "1; mode=block")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")
		h.Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
			if s.http3Server != nil {
				h.Set("Alt-Svc", `h3="`+s.config.ListenAddr+`"; ma=86400`)
			}
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/sub/") {
			h.Set("Content-Security-Policy", "default-src 'none'")
		} else {
			h.Set("Content-Security-Policy",
				"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'")
		}

		if strings.HasPrefix(r.URL.Path, "/api/") && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			origin := r.Header.Get("Origin")
			referer := r.Header.Get("Referer")
			if origin != "" && !s.isAllowedOrigin(origin) {
				http.Error(w, `{"error":"origin not allowed"}`, http.StatusForbidden)
				return
			}
			if origin == "" && referer == "" {
				ct := r.Header.Get("Content-Type")
				if !strings.Contains(ct, "application/json") && !strings.Contains(ct, "multipart/form-data") {
					http.Error(w, `{"error":"missing origin"}`, http.StatusForbidden)
					return
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) isAllowedOrigin(origin string) bool {
	if len(s.config.AllowedOrigins) == 0 || s.config.AllowedOrigins[0] == "*" {
		return true
	}
	for _, o := range s.config.AllowedOrigins {
		if strings.EqualFold(o, origin) {
			return true
		}
	}
	return false
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	authHdr := r.Header.Get("Authorization")
	if strings.HasPrefix(authHdr, "Bearer ") {
		token := authHdr[len("Bearer "):]
		if s.sessionToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.sessionToken)) == 1 {
			return true
		}
		if s.validateTimedToken(token) {
			return true
		}
	}
	if qt := r.URL.Query().Get("token"); qt != "" && s.validateTimedToken(qt) {
		return true
	}
	if claims := GetClaims(r); claims != nil && claims.HasRole(auth.RoleAdmin) {
		return true
	}
	http.Error(w, `{"error":"admin access required"}`, http.StatusForbidden)
	return false
}

const maxAPIBodyBytes = 1 << 20

func (s *Server) requestBodyLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			r.Body = http.MaxBytesReader(w, r.Body, maxAPIBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}

		if r.URL.Path == "/api/login" ||
			r.URL.Path == "/api/auth/login" ||
			r.URL.Path == "/api/v2/auth/login" ||
			r.URL.Path == "/api/v2/auth/register" ||
			r.URL.Path == "/api/v2/users/login" ||
			r.URL.Path == "/api/v2/auth/refresh" ||
			r.URL.Path == "/api/logout" ||
			r.URL.Path == "/api/keys/check" ||
			r.URL.Path == "/api/v1/speed/ping" ||
			strings.HasSuffix(r.URL.Path, "/health") {
			next.ServeHTTP(w, r)
			return
		}

		var token string
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if strings.HasPrefix(auth, prefix) {
			token = auth[len(prefix):]
		} else if qt := r.URL.Query().Get("token"); qt != "" {
			token = qt
		} else {
			w.Header().Set("WWW-Authenticate", `Bearer realm="api"`)
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		if s.sessionToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.sessionToken)) == 1 {
			next.ServeHTTP(w, r)
			return
		}

		if claims, err := s.jwtManager.ValidateAccessToken(token); err == nil {
			ctx := context.WithValue(r.Context(), ctxKeyClaims, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		if s.validateTimedToken(token) {
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Set("WWW-Authenticate", `Bearer realm="api", error="invalid_token", error_description="token expired or invalid"`)
		http.Error(w, `{"error":"session expired"}`, http.StatusUnauthorized)
	})
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.inflight.Add(1)
		defer s.inflight.Done()
		start := time.Now()
		next.ServeHTTP(w, r)
		s.UpdateActivity()
		_ = start
	})
}

func (s *Server) timeoutMiddleware(next http.Handler, timeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) connLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if i := strings.LastIndex(ip, ":"); i >= 0 {
			ip = ip[:i]
		}
		ip = strings.Trim(ip, "[]")

		s.activeConnsMu.Lock()
		count := s.activeConns[ip]
		if int(count) >= s.maxConnsPerIP {
			s.activeConnsMu.Unlock()
			http.Error(w, `{"error":"too many connections"}`, http.StatusTooManyRequests)
			return
		}
		s.activeConns[ip] = count + 1
		s.activeConnsMu.Unlock()

		defer func() {
			s.activeConnsMu.Lock()
			s.activeConns[ip]--
			if s.activeConns[ip] <= 0 {
				delete(s.activeConns, ip)
			}
			s.activeConnsMu.Unlock()
		}()

		next.ServeHTTP(w, r)
	})
}

func (s *Server) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				stack := make([]byte, 4096)
				n := runtime.Stack(stack, false)
				log.Error("panic: %v\n%s", err, stack[:n])

				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Internal Server Error",
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type apiRateBucket struct {
	tokens   float64
	lastTime time.Time
}

func (s *Server) apiRateMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}

		ip := s.getClientIP(r)
		key := ip + "|" + r.URL.Path

		s.apiRateBucketsMu.Lock()
		now := time.Now()

		if now.Sub(s.apiRateClean) > 5*time.Minute {
			cutoff := now.Add(-10 * time.Minute)
			for k, b := range s.apiRateBuckets {
				if b.lastTime.Before(cutoff) {
					delete(s.apiRateBuckets, k)
				}
			}
			s.apiRateClean = now
		}

		b, exists := s.apiRateBuckets[key]
		if !exists {
			b = &apiRateBucket{tokens: 60, lastTime: now}
			s.apiRateBuckets[key] = b
		}

		elapsed := now.Sub(b.lastTime).Seconds()
		b.lastTime = now
		b.tokens += elapsed * 30
		if b.tokens > 60 {
			b.tokens = 60
		}

		allowed := b.tokens >= 1
		if allowed {
			b.tokens--
		}
		s.apiRateBucketsMu.Unlock()

		if !allowed {
			w.Header().Set("Retry-After", "2")
			http.Error(w, `{"error":"too many requests"}`, http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}
