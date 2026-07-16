package mlserver

import (
	"encoding/json"
	"github.com/nekoskin/whispera/neural"
	"net/http"
	"time"
)

func (s *MLServer) handleFeedbackConnection(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Transport string  `json:"transport"`
		Success   bool    `json:"success"`
		Latency   float64 `json:"latency_ms"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	s.feedbackMu.Lock()
	ts, ok := s.transportStats[req.Transport]
	if !ok {
		ts = &TransportStats{}
		s.transportStats[req.Transport] = ts
	}
	ts.Total++
	if req.Success {
		ts.Success++
	} else {
		ts.Fail++
	}
	ts.TotalLatency += req.Latency
	ts.Count++
	s.feedbackMu.Unlock()

	s.engine.RecordBlockEvent(req.Transport, req.Success)
	if tspuDet := s.engine.GetTSPUDetector(); tspuDet != nil {
		if !req.Success && req.Latency < float64(neural.TSPURSTThresholdMs) {
			tspuDet.RecordRST("", time.Duration(req.Latency)*time.Millisecond)
		}
	}

	if rlAgent := s.engine.RLAgent(); rlAgent != nil {
		reward := neural.ComputeReward(req.Success, req.Latency)
		actionIdx := rlAgent.TransportIndex(req.Transport)
		if actionIdx >= 0 {
			state := make([]float64, neural.RLStateSize)
			rlAgent.RecordExperience(state, actionIdx, reward, state, !req.Success)
			bufSize := rlAgent.Stats()["buffer_size"].(int)
			if bufSize == neural.RLBatchSize*4+1 {
			}
		}
	}

	s.addLogf("feedback: %s success=%v latency=%.0fms", req.Transport, req.Success, req.Latency)
	s.jsonReply(w, map[string]string{"status": "ok"})
}

func (s *MLServer) handleFeedbackStats(w http.ResponseWriter, r *http.Request) {
	s.feedbackMu.Lock()
	stats := make(map[string]*TransportStats)
	for k, v := range s.transportStats {
		cp := *v
		stats[k] = &cp
	}
	s.feedbackMu.Unlock()
	s.jsonReply(w, stats)
}
