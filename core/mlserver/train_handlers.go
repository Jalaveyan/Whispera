package mlserver

import (
	"math"
	"net/http"
	"strconv"
)

func (s *MLServer) handleTrainStart(w http.ResponseWriter, r *http.Request) {
	if s.engine.IsTraining() {
		s.jsonReply(w, map[string]string{"status": "already_running"})
		return
	}

	epochs := 50
	if v := r.URL.Query().Get("epochs"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			epochs = n
		}
	}

	go func() {
		s.addLogf("training started (%d epochs)", epochs)
		samples, acc := s.engine.Train(epochs)
		s.addLogf("training done: %d samples, accuracy=%.4f", samples, acc)
	}()

	s.jsonReply(w, map[string]string{"status": "started"})
}

func (s *MLServer) handleTrainStop(w http.ResponseWriter, r *http.Request) {
	s.engine.StopTraining()
	s.addLogf("training stop requested")
	s.jsonReply(w, map[string]string{"status": "stopping"})
}

func (s *MLServer) handleTrainStatus(w http.ResponseWriter, r *http.Request) {
	running, epoch, total, loss := s.engine.TrainingStatus()
	if math.IsNaN(loss) || math.IsInf(loss, 0) {
		loss = 0
	}
	s.jsonReply(w, map[string]interface{}{
		"running":      running,
		"epoch":        epoch,
		"total_epochs": total,
		"loss":         loss,
	})
}
