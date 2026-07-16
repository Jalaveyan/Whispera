package mlserver

import (
	"encoding/json"
	"github.com/nekoskin/whispera/neural"
	"net/http"
	"time"
)

func (s *MLServer) handleTSPUStats(w http.ResponseWriter, r *http.Request) {
	if tspuDet := s.engine.GetTSPUDetector(); tspuDet != nil {
		tType, tConf := tspuDet.DetectTSPU()
		stats := tspuDet.Stats()
		stats["detected_type"] = tType
		stats["detected_confidence"] = tConf
		if tType != neural.DPITypeNone {
			stats["countermeasure"] = neural.TSPUCountermeasure(tType)
		}
		s.jsonReply(w, stats)
	} else {
		s.jsonReply(w, map[string]string{"status": "tspu_detector_not_initialized"})
	}
}

func (s *MLServer) handleTSPURST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SNI       string  `json:"sni"`
		TimeToRST float64 `json:"time_to_rst_ms"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if tspuDet := s.engine.GetTSPUDetector(); tspuDet != nil {
		tspuDet.RecordRST(req.SNI, time.Duration(req.TimeToRST)*time.Millisecond)
	}
	s.addLogf("tspu_rst: sni=%s time=%.1fms", req.SNI, req.TimeToRST)
	s.jsonReply(w, map[string]string{"status": "ok"})
}

func (s *MLServer) handleTSPUBandwidth(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Transport   string  `json:"transport"`
		BytesPerSec float64 `json:"bytes_per_sec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if tspuDet := s.engine.GetTSPUDetector(); tspuDet != nil {
		tspuDet.RecordBandwidth(req.Transport, req.BytesPerSec)
	}
	s.jsonReply(w, map[string]string{"status": "ok"})
}
