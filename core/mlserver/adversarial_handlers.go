package mlserver

import (
	"encoding/json"
	"net/http"
	"whispera/neural/evasion"
)

func (s *MLServer) handleAdversarialStatus(w http.ResponseWriter, r *http.Request) {
	if s.adversarial == nil {
		http.Error(w, "adversarial engine not initialized", http.StatusServiceUnavailable)
		return
	}
	s.jsonReply(w, s.adversarial.GetStats())
}

func (s *MLServer) handleAdversarialEvolve(w http.ResponseWriter, r *http.Request) {
	if s.adversarial == nil {
		http.Error(w, "adversarial engine not initialized", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Data []byte `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if len(req.Data) == 0 {
		req.Data = make([]byte, 256)
	}
	perturbed := s.adversarial.Apply(req.Data)
	s.addLogf("adversarial evolve: input=%d output=%d", len(req.Data), len(perturbed))
	s.jsonReply(w, map[string]interface{}{
		"input_size":  len(req.Data),
		"output_size": len(perturbed),
		"stats":       s.adversarial.GetStats(),
	})
}

func (s *MLServer) handleAdversarialFeedback(w http.ResponseWriter, r *http.Request) {
	if s.adversarial == nil {
		http.Error(w, "adversarial engine not initialized", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Detected  bool    `json:"detected"`
		Data      []byte  `json:"data"`
		Strategy  int     `json:"strategy"`
		Intensity float64 `json:"intensity"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	me := evasion.NewMLEvasion()
	features := me.CalculateMLFeatures(req.Data)
	var fArr [16]float64
	for i := 0; i < 16 && i < len(features); i++ {
		fArr[i] = features[i]
	}
	s.adversarial.RecordFeedback(req.Detected, req.Strategy, req.Intensity, fArr)
	s.addLogf("adversarial feedback: detected=%v strategy=%d", req.Detected, req.Strategy)
	s.jsonReply(w, map[string]interface{}{"status": "ok"})
}
