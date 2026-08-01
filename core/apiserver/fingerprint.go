package apiserver

import (
	"encoding/base64"
	"encoding/json"
	"github.com/nekoskin/whispera/core/protocol/fingerprint"
	"net/http"
)

const FingerprintStoreDir = "/etc/whispera/fingerprints"

func (s *Server) handleGetFingerprints(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.jsonOK(w, map[string]interface{}{
		"collected_count":    fingerprint.CollectedCount(),
		"collected_capacity": fingerprint.CollectedCapacity(),
	})
}

func (s *Server) handleSetFingerprint(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}

	var req struct {
		ClientHelloB64 string `json:"client_hello_b64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ClientHelloB64 == "" {
		s.jsonError(w, http.StatusBadRequest, "client_hello_b64 required")
		return
	}

	record, err := base64.StdEncoding.DecodeString(req.ClientHelloB64)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid base64: "+err.Error())
		return
	}

	if err := fingerprint.PersistRawFingerprint(FingerprintStoreDir, record); err != nil {
		s.jsonError(w, http.StatusBadRequest, "fingerprint: "+err.Error())
		return
	}
	_ = fingerprint.CollectRawClientHello(record)

	s.jsonOK(w, map[string]interface{}{
		"message":         "fingerprint stored",
		"collected_count": fingerprint.CollectedCount(),
	})
}
