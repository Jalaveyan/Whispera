package mlserver

import (
	"net/http"
	"strconv"
)

func (s *MLServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	n := 150
	if v := r.URL.Query().Get("n"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			n = parsed
		}
	}
	s.logMu.Lock()
	lines := s.logLines
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := make([]string, len(lines))
	copy(out, lines)
	s.logMu.Unlock()
	s.jsonReply(w, map[string]interface{}{"lines": out})
}

func (s *MLServer) handleLogsClear(w http.ResponseWriter, r *http.Request) {
	s.logMu.Lock()
	s.logLines = s.logLines[:0]
	s.logMu.Unlock()
	s.jsonReply(w, map[string]string{"status": "ok"})
}
