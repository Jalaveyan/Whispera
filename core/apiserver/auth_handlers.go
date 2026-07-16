package apiserver

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/nekoskin/whispera/app/auth"
	"github.com/nekoskin/whispera/app/db"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const sessionTokenFile = "/etc/whispera/session.token"
const signingSecretFile = "/etc/whispera/signing.key"
const tokenTTL = 30 * time.Minute

func loadOrCreateSessionToken() string {
	data, err := os.ReadFile(sessionTokenFile)
	if err == nil {
		token := strings.TrimSpace(string(data))
		if token != "" {
			return token
		}
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		log.Error("failed to generate session token: %v", err)
		return base64.StdEncoding.EncodeToString([]byte("fallback-token"))
	}
	token := base64.StdEncoding.EncodeToString(tokenBytes)
	_ = os.WriteFile(sessionTokenFile, []byte(token), 0600)
	return token
}

func loadOrCreateSigningSecret() []byte {
	data, err := os.ReadFile(signingSecretFile)
	if err == nil && len(data) >= 32 {
		return data[:32]
	}
	secret := make([]byte, 32)
	rand.Read(secret)
	os.WriteFile(signingSecretFile, secret, 0600)
	return secret
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	clientIP := s.getClientIP(r)
	if !s.checkLoginRateLimit(clientIP) {
		AppendEvent(EventAuth, SeverityWarn, "rate limit exceeded", map[string]string{"ip": clientIP})
		s.jsonError(w, http.StatusTooManyRequests, "Too many login attempts. Please wait 1 minute.")
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if database := db.Global(); database != nil {
		user, err := database.AuthenticateUser(r.Context(), req.Username, req.Password)
		if err == nil && user.IsAdmin {
			s.clearLoginAttempts(clientIP)
			AppendEvent(EventAuth, SeverityInfo, "login success", map[string]string{"ip": clientIP, "user": req.Username})

			token := s.issueTimedToken(req.Username)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":    true,
				"token":      token,
				"expires_in": 1800,
				"user": map[string]string{
					"username": req.Username,
					"role":     "admin",
					"id":       user.ID.String(),
				},
			})
			return
		}
	}

	expectedUsername := s.config.AdminUsername
	expectedPassword := s.config.AdminPassword

	if expectedUsername == "" {
		expectedUsername = "admin"
	}

	usernameMatch := subtle.ConstantTimeCompare([]byte(req.Username), []byte(expectedUsername)) == 1
	var passwordMatch bool
	if s.config.AdminPasswordHash != "" {
		passwordMatch = usernameMatch && bcrypt.CompareHashAndPassword([]byte(s.config.AdminPasswordHash), []byte(req.Password)) == nil
	} else if expectedPassword != "" {
		passwordMatch = subtle.ConstantTimeCompare([]byte(req.Password), []byte(expectedPassword)) == 1
	}

	if usernameMatch && passwordMatch {
		s.clearLoginAttempts(clientIP)

		token := s.issueTimedToken(req.Username)
		AppendEvent(EventAuth, SeverityInfo, "login success", map[string]string{"ip": clientIP, "user": req.Username})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":    true,
			"token":      token,
			"expires_in": 1800,
			"user": map[string]string{
				"username": req.Username,
				"role":     "admin",
			},
		})
		return
	}

	AppendEvent(EventAuth, SeverityWarn, "login failed", map[string]string{"ip": clientIP, "user": req.Username})
	s.jsonError(w, http.StatusUnauthorized, "Invalid username or password")
}

func (s *Server) checkLoginRateLimit(ip string) bool {
	s.loginAttemptsMu.Lock()
	defer s.loginAttemptsMu.Unlock()

	limit := s.config.LoginRateLimit
	if limit <= 0 {
		limit = 5
	}

	now := time.Now()
	windowStart := now.Add(-1 * time.Minute)

	attempts := s.loginAttempts[ip]
	var recentAttempts []time.Time
	for _, t := range attempts {
		if t.After(windowStart) {
			recentAttempts = append(recentAttempts, t)
		}
	}

	if len(recentAttempts) >= limit {
		return false
	}

	s.loginAttempts[ip] = append(recentAttempts, now)
	return true
}

func (s *Server) clearLoginAttempts(ip string) {
	s.loginAttemptsMu.Lock()
	defer s.loginAttemptsMu.Unlock()
	delete(s.loginAttempts, ip)
}

func isTrustedProxy(ip string) bool {
	trusted := []string{
		"127.0.0.0/8",
		"::1/128",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range trusted {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

func (s *Server) getClientIP(r *http.Request) string {
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !isTrustedProxy(remoteIP) {
		return remoteIP
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			if ip != "" && !isTrustedProxy(ip) {
				return ip
			}
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	return remoteIP
}

func (s *Server) issueTimedToken(username string) string {
	expiry := time.Now().Add(tokenTTL).Unix()
	nonce := make([]byte, 8)
	rand.Read(nonce)
	payload := fmt.Sprintf("%s:%d:%s", username, expiry, base64.RawURLEncoding.EncodeToString(nonce))
	sig := computeHMAC(s.signingSecret, payload)
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (s *Server) validateTimedToken(token string) bool {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}

	s.revokedTokensMu.Lock()
	if _, revoked := s.revokedTokens[token]; revoked {
		s.revokedTokensMu.Unlock()
		return false
	}
	s.revokedTokensMu.Unlock()

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	payload := string(payloadBytes)
	expectedSig := computeHMAC(s.signingSecret, payload)
	if !hmacEqual(sigBytes, expectedSig) {
		return false
	}

	fields := strings.SplitN(payload, ":", 3)
	if len(fields) < 2 {
		return false
	}
	var expiry int64
	fmt.Sscanf(fields[1], "%d", &expiry)
	return time.Now().Unix() <= expiry
}

func (s *Server) revokeToken(token string) {
	s.revokedTokensMu.Lock()
	s.revokedTokens[token] = time.Now()
	s.revokedTokensMu.Unlock()
}

func (s *Server) cleanupRevokedTokens() {
	s.revokedTokensMu.Lock()
	cutoff := time.Now().Add(-tokenTTL)
	for t, revokedAt := range s.revokedTokens {
		if revokedAt.Before(cutoff) {
			delete(s.revokedTokens, t)
		}
	}
	s.revokedTokensMu.Unlock()
}

func computeHMAC(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func hmacEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := authHeader[7:]
		s.revokeToken(token)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func (s *Server) handleLoginV2(w http.ResponseWriter, r *http.Request) {
	clientIP := s.getClientIP(r)
	if !s.checkLoginRateLimit(clientIP) {
		s.jsonError(w, http.StatusTooManyRequests, "Too many login attempts")
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	var userID string
	var role auth.Role
	authenticated := false

	if database := db.Global(); database != nil {
		user, err := database.AuthenticateUser(r.Context(), req.Username, req.Password)
		if err == nil {
			userID = user.ID.String()
			if user.IsAdmin {
				role = auth.RoleAdmin
			} else {
				role = auth.RoleUser
			}
			authenticated = true
		}
	}

	if !authenticated {
		expectedUsername := s.config.AdminUsername
		expectedPassword := s.config.AdminPassword
		if expectedUsername == "" {
			expectedUsername = "admin"
		}
		if expectedPassword != "" {
			uMatch := subtle.ConstantTimeCompare([]byte(req.Username), []byte(expectedUsername)) == 1
			pMatch := subtle.ConstantTimeCompare([]byte(req.Password), []byte(expectedPassword)) == 1
			if uMatch && pMatch {
				userID = "admin"
				role = auth.RoleAdmin
				authenticated = true
			}
		}
	}

	if !authenticated {
		s.jsonError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	s.clearLoginAttempts(clientIP)

	deviceID := r.Header.Get("X-Device-ID")
	accessToken, refreshToken, err := s.jwtManager.IssueTokenPair(userID, role, deviceID)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "Failed to issue tokens")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"expires_in":    int(auth.AccessTokenTTL.Seconds()),
		"token_type":    "Bearer",
		"user": map[string]interface{}{
			"id":   userID,
			"role": string(role),
		},
	})
}

func (s *Server) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	accessToken, refreshToken, err := s.jwtManager.RefreshAccessToken(req.RefreshToken)
	if err != nil {
		s.jsonError(w, http.StatusUnauthorized, "Invalid or expired refresh token")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"expires_in":    int(auth.AccessTokenTTL.Seconds()),
		"token_type":    "Bearer",
	})
}

func (s *Server) handleLogoutV2(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := authHeader[7:]
		s.jwtManager.RevokeAccessToken(token)
	}

	var req struct {
		RefreshToken string `json:"refresh_token,omitempty"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.RefreshToken != "" {
		s.jwtManager.RevokeRefreshToken(req.RefreshToken)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (s *Server) IsKeyRevoked(keyID string) bool {
	if keyID == "" {
		return false
	}
	s.revokedKeysMu.RLock()
	_, revoked := s.revokedKeys[keyID]
	s.revokedKeysMu.RUnlock()
	return revoked
}

func (s *Server) loadRevokedKeys() {
	data, err := os.ReadFile("/etc/whispera/revoked_keys.json")
	if err != nil {
		return
	}
	s.revokedKeysMu.Lock()
	_ = json.Unmarshal(data, &s.revokedKeys)
	s.revokedKeysMu.Unlock()
}
