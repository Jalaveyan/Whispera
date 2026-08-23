package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/nekoskin/whispera/common/runtime/base"
)

const testAuthToken = "test-api-auth-token"

func newTestServer(t *testing.T) *Server {
	t.Helper()
	s := &Server{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: &Config{
			Enabled:    true,
			ListenAddr: ":0",
			EnableCORS: true,
			AuthToken:  testAuthToken,
		},
		mux:            http.NewServeMux(),
		handlers:       make(map[string]http.HandlerFunc),
		revokedKeys:    make(map[string]time.Time),
		activeConns:    make(map[string]int32),
		maxConnsPerIP:  50,
		apiRateBuckets: make(map[string]*apiRateBucket),
		apiRateClean:   time.Now(),
		startTime:      time.Now(),
	}
	s.registerDefaultRoutes()
	return s
}

func doRequest(handler http.Handler, method, path string, body interface{}, token string) *httptest.ResponseRecorder {
	var bodyReader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(data)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, path, bodyReader)
	if method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func parseJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var result map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse JSON response: %v\nbody: %s", err, rec.Body.String())
	}
	return result
}

func TestHealthEndpoint(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	rec := doRequest(handler, "GET", "/api/v1/health", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	result := parseJSON(t, rec)
	if result["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", result["status"])
	}
}

func TestAuthMiddleware_NoToken(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	rec := doRequest(handler, "GET", "/api/v1/status", nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	rec := doRequest(handler, "GET", "/api/v1/status", nil, "bogus-token")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with invalid token, got %d", rec.Code)
	}
}

func TestAuthMiddleware_AuthToken(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	rec := doRequest(handler, "GET", "/api/v1/status", nil, testAuthToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with the configured token, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAuthMiddleware_QueryToken(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	rec := doRequest(handler, "GET", "/api/v1/status?token="+testAuthToken, nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with the token in the query, got %d", rec.Code)
	}
}

func TestAuthMiddleware_EmptyConfiguredTokenRejects(t *testing.T) {
	s := newTestServer(t)
	s.config.AuthToken = ""
	handler := s.buildHandler()

	for _, token := range []string{"", "anything"} {
		rec := doRequest(handler, "GET", "/api/v1/status", nil, token)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("token %q: expected 401 when no token is configured, got %d", token, rec.Code)
		}
	}
}

func TestStatusEndpoint(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	rec := doRequest(handler, "GET", "/api/v1/status", nil, testAuthToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	result := parseJSON(t, rec)
	if result["version"] != ModuleVersion {
		t.Errorf("expected version=%s, got %v", ModuleVersion, result["version"])
	}
}

func TestGetConfig(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	rec := doRequest(handler, "GET", "/api/v1/config", nil, testAuthToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	result := parseJSON(t, rec)
	api, ok := result["api"].(map[string]interface{})
	if !ok {
		t.Fatal("expected api object")
	}
	if api["cors"] != true {
		t.Errorf("expected cors=true, got %v", api["cors"])
	}
}

func TestRemovedEndpointsAreGone(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	for _, path := range []string{"/api/login", "/api/logout", "/api/users", "/api/inbounds", "/api/v1/stats"} {
		rec := doRequest(handler, "GET", path, nil, testAuthToken)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s should be gone, got %d", path, rec.Code)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	rec := doRequest(handler, "GET", "/api/v1/health", nil, "")

	expectedHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
	}

	for header, expected := range expectedHeaders {
		got := rec.Header().Get(header)
		if got != expected {
			t.Errorf("expected %s=%s, got %q", header, expected, got)
		}
	}
}

func TestCORS_Preflight(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	req, _ := http.NewRequestWithContext(context.Background(), "OPTIONS", "/api/v1/health", nil)
	req.Header.Set("Origin", "http://127.0.0.1:3000")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
		t.Fatalf("expected 200/204 for preflight, got %d", rec.Code)
	}
}

func TestRequestBodyLimit(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	bigBody := make([]byte, 2<<20)
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "/api/outbounds/add", bytes.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testAuthToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatal("oversized body should not succeed")
	}
}

func TestConcurrentRequests(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	var wg sync.WaitGroup
	errors := make(chan error, 50)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := doRequest(handler, "GET", "/api/v1/health", nil, "")
			if rec.Code != http.StatusOK {
				errors <- &httpError{code: rec.Code}
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent request failed: %v", err)
	}
}

type httpError struct{ code int }

func (e *httpError) Error() string { return http.StatusText(e.code) }

func TestRootEndpoint(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	rec := doRequest(handler, "GET", "/", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	result := parseJSON(t, rec)
	if result["name"] != "Whispera API" {
		t.Errorf("expected name=Whispera API, got %v", result["name"])
	}
	if result["status"] != "running" {
		t.Errorf("expected status=running, got %v", result["status"])
	}
}

func TestConnLimitMiddleware(t *testing.T) {
	s := newTestServer(t)
	s.maxConnsPerIP = 2

	block := make(chan struct{})
	s.Handle("GET /api/v1/slow", func(w http.ResponseWriter, r *http.Request) {
		<-block
		w.WriteHeader(http.StatusOK)
	})
	handler := s.buildHandler()

	var wg sync.WaitGroup
	results := make([]int, 3)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			rec := doRequest(handler, "GET", "/api/v1/slow", nil, testAuthToken)
			results[idx] = rec.Code
		}(i)
	}

	time.Sleep(50 * time.Millisecond)

	wg.Add(1)
	go func() {
		defer wg.Done()
		rec := doRequest(handler, "GET", "/api/v1/slow", nil, testAuthToken)
		results[2] = rec.Code
	}()

	time.Sleep(50 * time.Millisecond)
	close(block)
	wg.Wait()
}

func TestProtectedEndpoints_RequireAuth(t *testing.T) {
	s := newTestServer(t)
	handler := s.buildHandler()

	endpoints := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/status"},
		{"GET", "/api/v1/config"},
		{"GET", "/api/outbounds"},
		{"GET", "/api/logs"},
		{"GET", "/api/backup"},
		{"GET", "/api/backup/list"},
		{"GET", "/api/fingerprints"},
	}

	for _, ep := range endpoints {
		rec := doRequest(handler, ep.method, ep.path, nil, "")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s should require auth, got %d", ep.method, ep.path, rec.Code)
		}
	}
}
