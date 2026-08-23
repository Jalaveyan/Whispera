package apiserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/nekoskin/whispera/common/fsown"
	"github.com/nekoskin/whispera/core/config"
	"time"
)

const (
	backupDataDir   = config.Dir
	adblockDataFile = config.Dir + "/adblock.json"
)

func readRawJSON(path string) json.RawMessage {
	data, err := os.ReadFile(path)
	if err != nil {
		return json.RawMessage("null")
	}
	return json.RawMessage(data)
}

func (s *Server) backupPayload() map[string]interface{} {
	backup := map[string]interface{}{
		"version":       "1",
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
		"users":         readRawJSON(userDataFile),
		"subscriptions": readRawJSON(subDataFile),
		"adblock":       readRawJSON(adblockDataFile),
	}
	if p, ok := configProviderAs[interface{ GetConfigPath() string }](s); ok {
		if data, err := os.ReadFile(p.GetConfigPath()); err == nil {
			backup["config_yaml"] = string(data)
		}
	}
	return backup
}

func (s *Server) handleGetBackup(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.jsonOK(w, s.backupPayload())
}

const maxBackupBodySize = 10 << 20

func (s *Server) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBackupBodySize)
	var payload map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid backup file")
		return
	}

	if err := os.MkdirAll(backupDataDir, 0755); err != nil {
		s.jsonError(w, http.StatusInternalServerError, "failed to access data dir")
		return
	}

	restored := []string{}
	failed := []string{}

	files := map[string]string{
		"users":         userDataFile,
		"subscriptions": subDataFile,
		"adblock":       adblockDataFile,
	}

	for key, path := range files {
		raw, ok := payload[key]
		if !ok || string(raw) == "null" {
			continue
		}
		if err := fsown.WriteFile(path, []byte(raw), 0600); err != nil {
			failed = append(failed, key)
		} else {
			restored = append(restored, key)
		}
	}

	loadUsers()
	loadSubscriptions()

	msg := fmt.Sprintf("Restored: %v", restored)
	if len(failed) > 0 {
		msg += fmt.Sprintf("; Failed: %v", failed)
	}

	s.jsonOK(w, map[string]interface{}{
		"success":  len(failed) == 0,
		"message":  msg,
		"restored": restored,
		"failed":   failed,
	})
}
