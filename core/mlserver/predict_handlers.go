package mlserver

import (
	"encoding/json"
	"net/http"
)

func (s *MLServer) handlePredictTraffic(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Data      []byte `json:"data"`
		Protocol  string `json:"protocol"`
		Direction string `json:"direction"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	resp := s.engine.Predict(req.Data, req.Protocol, req.Direction)
	s.jsonReply(w, resp)
}
