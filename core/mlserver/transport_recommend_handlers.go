package mlserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
	"whispera/neural"
)

func (s *MLServer) handleNetworkAnalyze(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if req.Port == 0 {
		req.Port = 443
	}

	s.addLogf("network analysis: %s:%d", req.Host, req.Port)

	targets := []struct {
		host string
		port int
	}{
		{req.Host, req.Port},
		{"1.1.1.1", 443},
		{"8.8.8.8", 443},
		{"google.com", 443},
		{"cloudflare.com", 443},
	}

	type probeResult struct {
		reachable bool
		rtt       time.Duration
	}
	results := make([]probeResult, len(targets))

	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(idx int, host string, port int) {
			defer wg.Done()
			start := time.Now()
			conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
			if err == nil {
				results[idx] = probeResult{reachable: true, rtt: time.Since(start)}
				conn.Close()
			}
		}(i, t.host, t.port)
	}
	wg.Wait()

	reachable := 0
	var totalRTT time.Duration
	rttCount := 0
	for _, r := range results {
		if r.reachable {
			reachable++
			totalRTT += r.rtt
			rttCount++
		}
	}

	var avgRTT *float64
	if rttCount > 0 {
		v := float64(totalRTT.Milliseconds()) / float64(rttCount)
		avgRTT = &v
	}

	dpiRisk := "low"
	if !results[0].reachable {
		dpiRisk = "critical"
	} else if reachable < 3 {
		dpiRisk = "high"
	} else if avgRTT != nil && *avgRTT > 500 {
		dpiRisk = "medium"
	}

	resp := map[string]interface{}{
		"dpi_risk":              dpiRisk,
		"avg_rtt_ms":            avgRTT,
		"reachable":             reachable,
		"total_probed":          len(targets),
		"recommended_transport": "tcp",
		"recommended_reason":    "direct connection available",
	}

	switch dpiRisk {
	case "critical":
		resp["recommended_transport"] = "vkwebrtc"
		resp["recommended_reason"] = "target unreachable, use WebRTC relay"
	case "high":
		resp["recommended_transport"] = "mirage"
		resp["recommended_reason"] = "significant blocking detected, use SNI bypass"
	case "medium":
		resp["recommended_transport"] = "meek"
		resp["recommended_reason"] = "some throttling detected, use domain fronting"
	}

	s.addLogf("analysis: dpi=%s reachable=%d/%d", dpiRisk, reachable, len(targets))
	s.jsonReply(w, resp)
}

func (s *MLServer) handleRecommendTransport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerHost string `json:"server_host"`
		ServerPort int    `json:"server_port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if req.ServerPort == 0 {
		req.ServerPort = 8443
	}

	probeTargets := []struct {
		host string
		port int
	}{
		{req.ServerHost, req.ServerPort},
		{"1.1.1.1", 443},
		{"8.8.8.8", 443},
		{req.ServerHost, 80},
	}

	rttData := make([]float64, len(probeTargets))
	for i, t := range probeTargets {
		start := time.Now()
		conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "tcp", net.JoinHostPort(t.host, strconv.Itoa(t.port)))
		if err != nil {
			rttData[i] = 9999
		} else {
			rttData[i] = float64(time.Since(start).Milliseconds())
			conn.Close()
		}
	}

	successRates := make(map[string]float64)
	latencies := make(map[string]float64)
	stats := s.engine.GetTransportStats()
	for name, v := range stats {
		if m, ok := v.(map[string]interface{}); ok {
			if rate, ok := m["rate"].(float64); ok {
				successRates[name] = rate
			}
			if avg, ok := m["avg_latency_ms"].(float64); ok {
				latencies[name] = avg
			}
		}
	}

	mlpTransport := s.engine.RecommendTransport(rttData, successRates, latencies)

	dpiRisk := "low"
	reachable := 0
	for _, rtt := range rttData {
		if rtt < 5000 {
			reachable++
		}
	}
	if reachable == 0 {
		dpiRisk = "critical"
	} else if rttData[0] > 5000 && reachable > 1 {
		dpiRisk = "high"
	} else if rttData[0] > 1000 {
		dpiRisk = "medium"
	}

	transport := mlpTransport
	confidence := 0.85
	reason := fmt.Sprintf("ML neural network selected based on %d probes, %d transport stats", len(rttData), len(stats))
	usedRL := false
	tspuDetected := false

	if tspuDet := s.engine.GetTSPUDetector(); tspuDet != nil {
		tType, tConf := tspuDet.DetectTSPU()
		if tType != neural.DPITypeNone && tConf > 0.5 {
			tspuDetected = true
			dpiRisk = "tspu"
			countermeasure := neural.TSPUCountermeasure(tType)
			if countermeasure != "" {
				transport = countermeasure
				confidence = tConf
				reason = fmt.Sprintf("TSPU detected (type=%d, conf=%.2f) -> countermeasure: %s",
					tType, tConf, countermeasure)
			}
		}
	}

	if rlAgent := s.engine.RLAgent(); rlAgent != nil {
		var rttArr [4]float64
		for i := 0; i < 4 && i < len(rttData); i++ {
			rttArr[i] = rttData[i]
		}
		var totalSuccess, totalFail float64
		for _, v := range stats {
			if m, ok := v.(map[string]interface{}); ok {
				if s, ok := m["success"].(int64); ok {
					totalSuccess += float64(s)
				}
				if f, ok := m["fail"].(int64); ok {
					totalFail += float64(f)
				}
			}
		}
		total := totalSuccess + totalFail
		succRate := 0.5
		failRate := 0.5
		if total > 0 {
			succRate = totalSuccess / total
			failRate = totalFail / total
		}
		blockRisk := s.engine.PredictBlockRisk(mlpTransport)
		dpiDetected := dpiRisk == "high" || dpiRisk == "critical"
		hour := time.Now().Hour()

		state := rlAgent.EncodeState(rttArr, succRate, failRate, dpiDetected, 0, hour, blockRisk)
		rlTransport, _, explored := rlAgent.SelectTransport(state)

		rlStats := rlAgent.Stats()
		bufSize, _ := rlStats["buffer_size"].(int)
		if bufSize > neural.RLBatchSize*4 && !explored && !tspuDetected {
			transport = rlTransport
			confidence = 0.90
			reason = fmt.Sprintf("RL-DQN selected (buffer=%d, eps=%.3f)", bufSize, rlStats["epsilon"])
			usedRL = true
		}
	}

	if len(stats) == 0 && !usedRL && !tspuDetected {
		confidence = 0.6
		reason = "ML selected (no historical feedback yet)"
	}

	s.jsonReply(w, map[string]interface{}{
		"dpi_risk":      dpiRisk,
		"transport":     transport,
		"options":       "",
		"description":   reason,
		"confidence":    confidence,
		"used_rl":       usedRL,
		"tspu_detected": tspuDetected,
	})
}
