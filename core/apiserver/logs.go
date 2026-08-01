package apiserver

import (
	logger "github.com/nekoskin/whispera/common/log"
	"net/http"
	"strconv"
)

func (s *Server) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}

	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	minLevel := logger.LevelDebug
	if v := r.URL.Query().Get("level"); v != "" {
		minLevel = logger.ParseLevel(v)
	}

	entries := logger.Snapshot(limit, minLevel)
	s.jsonOK(w, map[string]interface{}{
		"entries": entries,
		"count":   len(entries),
	})
}
