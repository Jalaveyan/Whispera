package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/nekoskin/whispera/common/runtime/interfaces"
	"github.com/nekoskin/whispera/common/runtime/lifecycle"
	"github.com/nekoskin/whispera/core/crypto"
	"github.com/nekoskin/whispera/core/session"
	"log"
	"net/http"
	"os"
	"time"

	_ "go.uber.org/automaxprocs"
)

var Version = "2.0.0"

type jsonSessionOpenResponse struct {
	SessionID  string `json:"session_id"`
	AEADKey    string `json:"aead_key"`
	Seed       string `json:"seed"`
	InitialSeq uint32 `json:"initial_seq"`
	ExpiresAt  string `json:"expires_at"`
}

type jsonSessionRefreshResponse struct {
	Renewed    bool   `json:"renewed"`
	ExpiresAt  string `json:"expires_at"`
	NewAEADKey string `json:"new_aead_key,omitempty"`
	NewSeq     uint32 `json:"new_seq"`
}

type jsonSessionCloseResponse struct {
	Closed bool `json:"closed"`
}

type sessionOpenRequest struct {
	ClientID  string `json:"client_id"`
	ClientKey string `json:"client_key"`
}

type sessionRefreshRequest struct {
	SessionID string `json:"session_id"`
}

type sessionCloseRequest struct {
	SessionID string `json:"session_id"`
}

func main() {
	var (
		listenAddr   = flag.String("listen", ":9090", "HTTP listen address")
		sessionTTL   = flag.Duration("session-ttl", time.Hour, "session lifetime duration")
		timeout      = flag.Duration("session-timeout", 2*time.Hour, "session manager inactivity timeout")
		printVersion = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()

	if *printVersion {
		log.Printf("Whispera v%s", Version)
		os.Exit(0)
	}

	manager := lifecycle.NewManager(lifecycle.Config{
		ShutdownTimeout: 10_000_000_000,
		GracefulStop:    true,
	})

	cryptoProvider, err := crypto.New(&crypto.Config{
		DefaultCipher: crypto.CipherChaCha20Poly1305,
		EnableKeyPool: true,
		KeyPoolSize:   50,
	})
	if err != nil {
		log.Fatalf("Failed to create crypto provider: %v", err)
	}
	if err := manager.Register(cryptoProvider); err != nil {
		log.Fatalf("Failed to register crypto provider: %v", err)
	}

	sessionMgr, err := session.New(&session.Config{
		MaxSessions:     10000,
		SessionTimeout:  *timeout,
		CleanupInterval: time.Minute,
	})
	if err != nil {
		log.Fatalf("Failed to create session manager: %v", err)
	}
	if err := manager.Register(sessionMgr); err != nil {
		log.Fatalf("Failed to register session manager: %v", err)
	}

	if err := manager.Start(); err != nil {
		log.Fatalf("Failed to start: %v", err)
	}

	svc := &authService{
		crypto:     cryptoProvider,
		sessions:   sessionMgr,
		sessionTTL: *sessionTTL,
		logger:     log.New(os.Stdout, "[authsvc] ", log.LstdFlags|log.Lmicroseconds),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/v1/sessions:open", svc.handleOpen)
	mux.HandleFunc("/v1/sessions:refresh", svc.handleRefresh)
	mux.HandleFunc("/v1/sessions:close", svc.handleClose)

	svc.logger.Printf("listening on %s", *listenAddr)
	server := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		svc.logger.Fatalf("server exited: %v", err)
	}
}

type authService struct {
	crypto     *crypto.Provider
	sessions   *session.Manager
	sessionTTL time.Duration
	logger     *log.Logger
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func decodePost(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
	if r.Method != http.MethodPost {
		httpError(w, http.StatusMethodNotAllowed, "POST required")
		return false
	}
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		httpError(w, http.StatusBadRequest, fmt.Sprintf("invalid json: %v", err))
		return false
	}
	return true
}

func (a *authService) handleOpen(w http.ResponseWriter, r *http.Request) {
	var req sessionOpenRequest
	if !decodePost(w, r, &req) {
		return
	}

	seed := make([]byte, 32)
	a.crypto.DeriveKey([]byte(req.ClientID+req.ClientKey), seed, 32)

	aeadKey := make([]byte, 32)
	a.crypto.DeriveKey(seed, aeadKey, 32)

	sess, err := a.sessions.CreateSession(interfaces.SessionParams{
		ClientAddr: nil,
		Seed:       seed,
		Metadata: map[string]interface{}{
			"client_id": req.ClientID,
			"ttl":       a.sessionTTL,
		},
	})
	if err != nil {
		a.logger.Printf("open session error: %v", err)
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, jsonSessionOpenResponse{
		SessionID:  fmt.Sprintf("%d", sess.ID()),
		AEADKey:    base64.StdEncoding.EncodeToString(aeadKey),
		Seed:       base64.StdEncoding.EncodeToString(seed),
		InitialSeq: 0,
		ExpiresAt:  time.Now().Add(a.sessionTTL).UTC().Format(time.RFC3339Nano),
	})
}

func (a *authService) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req sessionRefreshRequest
	if !decodePost(w, r, &req) {
		return
	}

	var sessionID uint32
	fmt.Sscanf(req.SessionID, "%d", &sessionID)

	sess, ok := a.sessions.GetSession(sessionID)
	if !ok {
		httpError(w, http.StatusNotFound, "session not found")
		return
	}

	sess.UpdateActivity()
	writeJSON(w, http.StatusOK, jsonSessionRefreshResponse{
		Renewed:   true,
		ExpiresAt: time.Now().Add(a.sessionTTL).UTC().Format(time.RFC3339Nano),
		NewSeq:    0,
	})
}

func (a *authService) handleClose(w http.ResponseWriter, r *http.Request) {
	var req sessionCloseRequest
	if !decodePost(w, r, &req) {
		return
	}

	var sessionID uint32
	fmt.Sscanf(req.SessionID, "%d", &sessionID)

	a.sessions.RemoveSession(sessionID)
	writeJSON(w, http.StatusOK, jsonSessionCloseResponse{
		Closed: true,
	})
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("write json error: %v", err)
	}
}

func httpError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{
		"error": message,
	})
}
