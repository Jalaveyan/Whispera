package mlserver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (s *MLServer) handleFedDatasetExport(w http.ResponseWriter, r *http.Request) {
	dsPath := filepath.Join(s.fedDir, "aggregated_dataset.jsonl")
	info, err := os.Stat(dsPath)
	if err != nil {
		s.jsonReply(w, map[string]interface{}{"error": "no dataset yet", "samples": 0})
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", "attachment; filename=whispera_ml_dataset.jsonl")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	http.ServeFile(w, r, dsPath)
}

func (s *MLServer) handleFedDatasetStats(w http.ResponseWriter, r *http.Request) {
	dsPath := filepath.Join(s.fedDir, "aggregated_dataset.jsonl")
	info, err := os.Stat(dsPath)
	if err != nil {
		s.jsonReply(w, map[string]interface{}{
			"samples": 0, "size_bytes": 0, "clients": 0,
		})
		return
	}

	entries, _ := os.ReadDir(s.fedDir)
	deltaCount := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "delta_") {
			deltaCount++
		}
	}

	s.jsonReply(w, map[string]interface{}{
		"samples":       s.datasetSampleCount(),
		"size_bytes":    info.Size(),
		"size_mb":       float64(info.Size()) / (1024 * 1024),
		"uploads":       deltaCount,
		"last_modified": info.ModTime().UTC().Format(time.RFC3339),
	})
}

func (s *MLServer) handleDatasetsList(w http.ResponseWriter, r *http.Request) {
	dsDir := filepath.Join(s.dataDir, "datasets")
	os.MkdirAll(dsDir, 0700)

	entries, _ := os.ReadDir(dsDir)
	var datasets []map[string]interface{}
	for _, e := range entries {
		if !e.IsDir() {
			info, _ := e.Info()
			if info != nil {
				datasets = append(datasets, map[string]interface{}{
					"name":     e.Name(),
					"size":     info.Size(),
					"modified": info.ModTime().Unix(),
				})
			}
		}
	}
	s.jsonReply(w, map[string]interface{}{"datasets": datasets})
}

func (s *MLServer) handleDatasetsCapture(w http.ResponseWriter, r *http.Request) {
	dsDir := filepath.Join(s.dataDir, "datasets")
	os.MkdirAll(dsDir, 0700)

	name := fmt.Sprintf("capture_%d.jsonl", time.Now().Unix())
	fpath := filepath.Join(dsDir, name)

	s.feedbackMu.Lock()
	stats := make(map[string]*TransportStats)
	for k, v := range s.transportStats {
		cp := *v
		stats[k] = &cp
	}
	s.feedbackMu.Unlock()

	data, _ := json.Marshal(map[string]interface{}{
		"ts":         time.Now().Unix(),
		"transports": stats,
		"model":      s.engine.GetStats(),
	})
	os.WriteFile(fpath, data, 0600)

	s.addLogf("dataset captured: %s", name)
	s.jsonReply(w, map[string]interface{}{"status": "ok", "name": name})
}

func (s *MLServer) handleDatasetsUpload(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil || len(body) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}
	dsDir := filepath.Join(s.dataDir, "datasets")
	os.MkdirAll(dsDir, 0700)

	name := r.Header.Get("X-Dataset-Name")
	if name == "" {
		name = fmt.Sprintf("upload_%d.jsonl", time.Now().Unix())
	}
	name = filepath.Base(name)
	os.WriteFile(filepath.Join(dsDir, name), body, 0600)
	s.addLogf("dataset uploaded: %s (%d bytes)", name, len(body))
	s.jsonReply(w, map[string]interface{}{"status": "ok", "name": name, "size": len(body)})
}

func (s *MLServer) handleDatasetsExchange(w http.ResponseWriter, r *http.Request) {
	s.jsonReply(w, map[string]interface{}{
		"status": "exchange requires peer_url, use Python server for P2P",
	})
}
