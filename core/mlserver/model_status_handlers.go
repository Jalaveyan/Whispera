package mlserver

import (
	"net/http"
	"time"
)

func (s *MLServer) handleModelsStatus(w http.ResponseWriter, r *http.Request) {
	stats := s.engine.GetStats()
	samples, _ := stats["samples"].(int64)
	retrains, _ := stats["retrains"].(int64)
	accuracy, _ := stats["accuracy"].(float64)
	isTrained := samples > 0 || retrains > 0 || accuracy > 0
	lastTrained, _ := stats["last_trained"].(int64)
	lastUpdated := time.Unix(lastTrained, 0).Format(time.RFC3339)
	if lastTrained == 0 {
		lastUpdated = ""
	}
	s.jsonReply(w, map[string]interface{}{
		"models": []map[string]interface{}{
			{
				"model_name":   "traffic_classifier",
				"is_trained":   isTrained,
				"accuracy":     accuracy,
				"last_updated": lastUpdated,
				"parameters":   stats["parameters"],
			},
		},
		"engine": "native_mlp_go",
		"stats":  stats,
	})
}

func (s *MLServer) handleModelsLoad(w http.ResponseWriter, r *http.Request) {
	s.addLogf("model reload requested")
	s.jsonReply(w, map[string]string{"status": "loaded"})
}

func (s *MLServer) handleSelfLearningStatus(w http.ResponseWriter, r *http.Request) {
	stats := s.engine.GetStats()
	s.jsonReply(w, map[string]interface{}{
		"samples_collected": stats["samples"],
		"predictions_made":  stats["predictions"],
		"accuracy":          stats["accuracy"],
		"model":             stats["model"],
	})
}
