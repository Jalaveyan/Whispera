package obfuscation

import (
	"context"
	"math"
	"strings"
	"sync"
	"time"

	"whispera/internal/util"
)

type DetectInjection struct {
	detectors map[string]*DPIDetector
	results   map[string]*InjectionResult
	mu        sync.RWMutex
}

type DPIDetector struct {
	Name      string
	Type      string
	Threshold float64
	Window    time.Duration
	Enabled   bool
	Rules     []*DPIRule
}

type DPIRule struct {
	Name        string
	Type        string
	Pattern     string
	Weight      float64
	Threshold   float64
	Description string
}

type InjectionResult struct {
	Timestamp       time.Time
	SimulatorName   string
	Score           float64
	Detected        bool
	Confidence      float64
	Details         map[string]interface{}
	Recommendations []string
}

func NewDetectInjection() *DetectInjection {
	di := &DetectInjection{
		detectors: make(map[string]*DPIDetector),
		results:   make(map[string]*InjectionResult),
	}
	di.initDetectors()
	return di
}

func (di *DetectInjection) initDetectors() {
	di.detectors["deep_packet"] = &DPIDetector{
		Name:      "Deep Packet Inspection",
		Type:      "deep_packet",
		Threshold: 0.7,
		Window:    30 * time.Second,
		Enabled:   true,
		Rules: []*DPIRule{
			{
				Name:        "TLS Handshake Pattern",
				Type:        "signature",
				Pattern:     "16 03 01 00 [0-9A-F]{2} 01 00 00 [0-9A-F]{2} 03 03",
				Weight:      0.3,
				Threshold:   0.8,
				Description: "Паттерн TLS handshake",
			},
			{
				Name:        "HTTP/2 Frame Pattern",
				Type:        "signature",
				Pattern:     "00 00 [0-9A-F]{2} [0-9A-F]{2} [0-9A-F]{2}",
				Weight:      0.25,
				Threshold:   0.7,
				Description: "Паттерн HTTP/2 фреймов",
			},
			{
				Name:        "WebSocket Frame Pattern",
				Type:        "signature",
				Pattern:     "81 [0-9A-F]{2} [0-9A-F]{8}",
				Weight:      0.2,
				Threshold:   0.6,
				Description: "Паттерн WebSocket фреймов",
			},
		},
	}

	di.detectors["flow_analysis"] = &DPIDetector{
		Name:      "Flow Analysis",
		Type:      "flow_analysis",
		Threshold: 0.6,
		Window:    60 * time.Second,
		Enabled:   true,
		Rules: []*DPIRule{
			{
				Name:        "Packet Size Distribution",
				Type:        "statistical",
				Pattern:     "size_distribution",
				Weight:      0.4,
				Threshold:   0.5,
				Description: "Распределение размеров пакетов",
			},
			{
				Name:        "Timing Pattern",
				Type:        "statistical",
				Pattern:     "timing_pattern",
				Weight:      0.3,
				Threshold:   0.4,
				Description: "Паттерн временных интервалов",
			},
			{
				Name:        "Burst Pattern",
				Type:        "behavioral",
				Pattern:     "burst_pattern",
				Weight:      0.3,
				Threshold:   0.6,
				Description: "Паттерн пакетных всплесков",
			},
		},
	}

	di.detectors["behavioral"] = &DPIDetector{
		Name:      "Behavioral Analysis",
		Type:      "behavioral",
		Threshold: 0.5,
		Window:    5 * time.Minute,
		Enabled:   true,
		Rules: []*DPIRule{
			{
				Name:        "Session Duration",
				Type:        "behavioral",
				Pattern:     "session_duration",
				Weight:      0.25,
				Threshold:   0.3,
				Description: "Длительность сессии",
			},
			{
				Name:        "Request Pattern",
				Type:        "behavioral",
				Pattern:     "request_pattern",
				Weight:      0.35,
				Threshold:   0.4,
				Description: "Паттерн запросов",
			},
			{
				Name:        "Error Pattern",
				Type:        "behavioral",
				Pattern:     "error_pattern",
				Weight:      0.4,
				Threshold:   0.5,
				Description: "Паттерн ошибок",
			},
		},
	}

	di.detectors["statistical"] = &DPIDetector{
		Name:      "Statistical Analysis",
		Type:      "statistical",
		Threshold: 0.4,
		Window:    10 * time.Minute,
		Enabled:   true,
		Rules: []*DPIRule{
			{
				Name:        "Entropy Analysis",
				Type:        "statistical",
				Pattern:     "entropy",
				Weight:      0.3,
				Threshold:   0.6,
				Description: "Анализ энтропии",
			},
			{
				Name:        "Correlation Analysis",
				Type:        "statistical",
				Pattern:     "correlation",
				Weight:      0.35,
				Threshold:   0.5,
				Description: "Корреляционный анализ",
			},
			{
				Name:        "Anomaly Detection",
				Type:        "statistical",
				Pattern:     "anomaly",
				Weight:      0.35,
				Threshold:   0.4,
				Description: "Детекция аномалий",
			},
		},
	}
}

func (di *DetectInjection) RunInjectionTest(
	ctx context.Context, profile string, data *InjectionData,
) ([]*InjectionResult, error) {
	di.mu.Lock()
	defer di.mu.Unlock()

	results := make([]*InjectionResult, 0, len(di.detectors))

	for detName, detector := range di.detectors {
		if !detector.Enabled {
			continue
		}

		result := di.runDetector(ctx, detector, profile, data)
		results = append(results, result)
		di.results[detName] = result
	}

	return results, nil
}

type InjectionData struct {
	Packets    []*PacketData
	Flows      []*FlowData
	Sessions   []*SessionData
	Timestamps []time.Time
	Profile    string
	Duration   time.Duration
}

type PacketData struct {
	Size      int
	Timestamp time.Time
	Protocol  string
	Payload   []byte
	Headers   map[string]string
	Direction string
}

type FlowData struct {
	ID         string
	StartTime  time.Time
	EndTime    time.Time
	Packets    int
	Bytes      int64
	Protocol   string
	SourceIP   string
	DestIP     string
	SourcePort int
	DestPort   int
}

type SessionData struct {
	ID        string
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration
	Requests  int
	Responses int
	Errors    int
	Bytes     int64
	UserAgent string
	Referer   string
}

func (di *DetectInjection) runDetector(
	ctx context.Context, detector *DPIDetector, profile string, data *InjectionData,
) *InjectionResult {
	select {
	case <-ctx.Done():
		return &InjectionResult{
			Timestamp:       util.GetGlobalTimeCache().Now(),
			SimulatorName:   detector.Name,
			Score:           0.0,
			Detected:        false,
			Confidence:      0.0,
			Details:         map[string]interface{}{"error": "context canceled"},
			Recommendations: []string{},
		}
	default:
	}

	result := &InjectionResult{
		Timestamp:       util.GetGlobalTimeCache().Now(),
		SimulatorName:   detector.Name,
		Details:         make(map[string]interface{}),
		Recommendations: make([]string, 0),
	}

	switch detector.Type {
	case "deep_packet":
		result = di.detectDeepPacket(detector, profile, data)
	case "flow_analysis":
		result = di.detectFlowAnalysis(detector, profile, data)
	case "behavioral":
		result = di.detectBehavioral(detector, profile, data)
	case "statistical":
		result = di.detectStatistical(detector, profile, data)
	default:
		result.Score = 0.0
		result.Detected = false
		result.Confidence = 0.0
		result.Details["error"] = "неизвестный тип детектора"
	}

	result.Details["profile"] = profile
	return result
}

func (di *DetectInjection) detectDeepPacket(
	detector *DPIDetector, profile string, data *InjectionData,
) *InjectionResult {
	result := &InjectionResult{
		Timestamp:       util.GetGlobalTimeCache().Now(),
		SimulatorName:   detector.Name,
		Details:         make(map[string]interface{}),
		Recommendations: make([]string, 0),
	}

	totalScore := 0.0
	matchedRules := 0

	for _, rule := range detector.Rules {
		score := di.analyzeRule(rule, data)
		if score > rule.Threshold {
			totalScore += score * rule.Weight
			matchedRules++
		}
	}

	result.Score = totalScore
	result.Detected = totalScore >= detector.Threshold
	result.Confidence = math.Min(1.0, totalScore)

	result.Details["matched_rules"] = matchedRules
	result.Details["total_rules"] = len(detector.Rules)
	result.Details["total_score"] = totalScore
	result.Details["threshold"] = detector.Threshold
	result.Details["profile"] = profile

	if result.Detected {
		result.Recommendations = append(result.Recommendations,
			"Обнаружены подозрительные паттерны в пакетах",
			"Измените структуру пакетов для лучшей маскировки")
	}

	return result
}

func (di *DetectInjection) detectFlowAnalysis(
	detector *DPIDetector, profile string, data *InjectionData,
) *InjectionResult {
	result := &InjectionResult{
		Timestamp:       util.GetGlobalTimeCache().Now(),
		SimulatorName:   detector.Name,
		Details:         make(map[string]interface{}),
		Recommendations: make([]string, 0),
	}

	totalScore := 0.0
	analyzedFlows := 0

	for _, rule := range detector.Rules {
		score := di.analyzeFlowRule(rule, data)
		if score > rule.Threshold {
			totalScore += score * rule.Weight
			analyzedFlows++
		}
	}

	flowScore := di.analyzeFlowCharacteristics(data.Flows)
	totalScore += flowScore * 0.3

	result.Score = totalScore
	result.Detected = totalScore >= detector.Threshold
	result.Confidence = math.Min(1.0, totalScore)

	result.Details["analyzed_flows"] = analyzedFlows
	result.Details["total_flows"] = len(data.Flows)
	result.Details["total_score"] = totalScore
	result.Details["threshold"] = detector.Threshold
	result.Details["profile"] = profile

	if result.Detected {
		result.Recommendations = append(result.Recommendations,
			"Обнаружены подозрительные паттерны в потоках",
			"Измените паттерны трафика для лучшей маскировки")
	}

	return result
}

func (di *DetectInjection) detectBehavioral(
	detector *DPIDetector, profile string, data *InjectionData,
) *InjectionResult {
	result := &InjectionResult{
		Timestamp:       util.GetGlobalTimeCache().Now(),
		SimulatorName:   detector.Name,
		Details:         make(map[string]interface{}),
		Recommendations: make([]string, 0),
	}

	totalScore := 0.0
	analyzedSessions := 0

	for _, rule := range detector.Rules {
		score := di.analyzeBehavioralRule(rule, data)
		if score > rule.Threshold {
			totalScore += score * rule.Weight
			analyzedSessions++
		}
	}

	sessionScore := di.analyzeSessionBehavior(data.Sessions)
	totalScore += sessionScore * 0.4

	result.Score = totalScore
	result.Detected = totalScore >= detector.Threshold
	result.Confidence = math.Min(1.0, totalScore)

	result.Details["analyzed_sessions"] = analyzedSessions
	result.Details["total_sessions"] = len(data.Sessions)
	result.Details["total_score"] = totalScore
	result.Details["threshold"] = detector.Threshold
	result.Details["profile"] = profile

	if result.Detected {
		result.Recommendations = append(result.Recommendations,
			"Обнаружены подозрительные поведенческие паттерны",
			"Измените поведение для лучшей маскировки")
	}

	return result
}

func (di *DetectInjection) detectStatistical(
	detector *DPIDetector, profile string, data *InjectionData,
) *InjectionResult {
	result := &InjectionResult{
		Timestamp:       util.GetGlobalTimeCache().Now(),
		SimulatorName:   detector.Name,
		Details:         make(map[string]interface{}),
		Recommendations: make([]string, 0),
	}

	totalScore := 0.0
	analyzedMetrics := 0

	for _, rule := range detector.Rules {
		score := di.analyzeStatisticalRule(rule, data)
		if score > rule.Threshold {
			totalScore += score * rule.Weight
			analyzedMetrics++
		}
	}

	timingScore := di.analyzePacketTiming(data.Packets)
	entropyScore := di.analyzePayloadEntropy(data.Packets)
	anomalyScore := di.detectProtocolAnomalies(data.Packets)

	totalScore += (timingScore + entropyScore + anomalyScore) * 0.2

	result.Score = totalScore
	result.Detected = totalScore >= detector.Threshold
	result.Confidence = math.Min(1.0, totalScore)

	result.Details["analyzed_metrics"] = analyzedMetrics
	result.Details["total_rules"] = len(detector.Rules)
	result.Details["total_score"] = totalScore
	result.Details["threshold"] = detector.Threshold
	result.Details["profile"] = profile

	if result.Detected {
		result.Recommendations = append(result.Recommendations,
			"Обнаружены статистические аномалии",
			"Измените статистические характеристики трафика")
	}

	return result
}

func (di *DetectInjection) analyzeRule(rule *DPIRule, data *InjectionData) float64 {
	switch rule.Type {
	case "signature":
		return di.analyzeSignature(rule, data)
	case "pattern":
		return di.analyzePattern(rule, data)
	case "statistical":
		return di.analyzeStatistical(rule, data)
	case "behavioral":
		return di.analyzeBehavioral(rule, data)
	default:
		return 0.0
	}
}

func (di *DetectInjection) analyzeSignature(rule *DPIRule, data *InjectionData) float64 {
	matches := 0
	total := 0
	confidence := 0.0

	for _, packet := range data.Packets {
		total++
		if di.matchesSignature(packet.Payload, rule.Pattern) {
			matches++
			if di.verifyPacketHeaders(packet, rule) {
				confidence += 0.2
			}
		}
	}

	if total == 0 {
		return 0.0
	}

	baseScore := float64(matches) / float64(total)
	confidence = math.Min(1.0, confidence)

	sizeFactor := di.calculateSizeFactor(data.Packets)
	protocolFactor := di.calculateProtocolFactor(data.Packets)

	entropyFactor := di.calculateByteEntropy(concatPayloads(data.Packets))
	timingFactor := di.analyzePacketTiming(data.Packets)

	finalScore := (baseScore + confidence + sizeFactor + protocolFactor + entropyFactor/8.0 + timingFactor) / 6.0
	return math.Min(1.0, finalScore)
}

func (di *DetectInjection) analyzePattern(rule *DPIRule, data *InjectionData) float64 {
	matches := 0
	total := 0

	for _, packet := range data.Packets {
		total++
		if di.matchesPattern(packet.Payload, rule.Pattern) {
			matches++
		}
	}

	if total == 0 {
		return 0.0
	}

	return float64(matches) / float64(total)
}

func (di *DetectInjection) analyzeStatistical(rule *DPIRule, data *InjectionData) float64 {
	if len(data.Packets) == 0 {
		return 0.0
	}

	ruleWeight := 1.0
	if rule != nil && rule.Threshold > 0 {
		ruleWeight = rule.Threshold
	}

	entropy := di.calculateEntropy(data.Packets)

	correlation := di.calculateCorrelation(data.Packets)

	anomalies := di.detectAnomalies(data.Packets)

	score := (entropy + correlation + anomalies) / 3.0 * ruleWeight
	return math.Min(1.0, score)
}

func (di *DetectInjection) analyzeBehavioral(rule *DPIRule, data *InjectionData) float64 {
	if len(data.Sessions) == 0 {
		return 0.0
	}

	ruleWeight := 1.0
	if rule != nil && rule.Threshold > 0 {
		ruleWeight = rule.Threshold
	}

	sessionScore := di.analyzeSessionDuration(data.Sessions)

	requestScore := di.analyzeRequestPatterns(data.Sessions)

	errorScore := di.analyzeErrorPatterns(data.Sessions)

	score := (sessionScore + requestScore + errorScore) / 3.0 * ruleWeight
	return math.Min(1.0, score)
}

func (di *DetectInjection) analyzeFlowRule(rule *DPIRule, data *InjectionData) float64 {
	baseScore := 0.6
	if rule != nil && rule.Threshold > 0 {
		baseScore = rule.Threshold
	}
	if len(data.Packets) > 0 {
		baseScore += 0.1
	}
	return math.Min(1.0, baseScore)
}

func (di *DetectInjection) analyzeBehavioralRule(rule *DPIRule, data *InjectionData) float64 {
	baseScore := 0.5
	if rule != nil && rule.Threshold > 0 {
		baseScore = rule.Threshold
	}
	if len(data.Sessions) > 0 {
		baseScore += 0.1
	}
	return math.Min(1.0, baseScore)
}

func (di *DetectInjection) analyzeStatisticalRule(rule *DPIRule, data *InjectionData) float64 {
	baseScore := 0.4
	if rule != nil && rule.Threshold > 0 {
		baseScore = rule.Threshold
	}
	if len(data.Packets) > 0 {
		baseScore += 0.1
	}
	return math.Min(1.0, baseScore)
}

func (di *DetectInjection) matchesSignature(payload []byte, pattern string) bool {
	if len(payload) == 0 || pattern == "" {
		return false
	}

	switch pattern {
	case "16 03 01 00 [0-9A-F]{2} 01 00 00 [0-9A-F]{2} 03 03":
		return di.matchesTLSPattern(payload)
	case "00 00 [0-9A-F]{2} [0-9A-F]{2} [0-9A-F]{2}":
		return di.matchesHTTP2Pattern(payload)
	case "81 [0-9A-F]{2} [0-9A-F]{8}":
		return di.matchesWebSocketPattern(payload)
	default:
		return di.genericPatternMatch(payload, pattern)
	}
}

func (di *DetectInjection) matchesPattern(payload []byte, pattern string) bool {
	return len(payload) > 0 && pattern != ""
}

func (di *DetectInjection) calculateEntropy(packets []*PacketData) float64 {
	if len(packets) == 0 {
		return 0.0
	}

	freq := make(map[byte]int)
	total := 0

	for _, packet := range packets {
		for _, b := range packet.Payload {
			freq[b]++
			total++
		}
	}

	entropy := 0.0
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / float64(total)
			entropy -= p * math.Log2(p)
		}
	}

	return entropy / 8.0
}

func (di *DetectInjection) calculateCorrelation(packets []*PacketData) float64 {
	if len(packets) < 2 {
		return 0.0
	}

	sizes := make([]float64, len(packets))
	for i, packet := range packets {
		sizes[i] = float64(packet.Size)
	}

	mean := 0.0
	for _, size := range sizes {
		mean += size
	}
	mean /= float64(len(sizes))

	numerator := 0.0
	denomX := 0.0
	denomY := 0.0

	for i := 0; i < len(sizes)-1; i++ {
		x := sizes[i] - mean
		y := sizes[i+1] - mean
		numerator += x * y
		denomX += x * x
		denomY += y * y
	}

	if denomX == 0 || denomY == 0 {
		return 0.0
	}

	correlation := numerator / math.Sqrt(denomX*denomY)
	return math.Abs(correlation)
}

func (di *DetectInjection) detectAnomalies(packets []*PacketData) float64 {
	if len(packets) == 0 {
		return 0.0
	}

	sizes := make([]float64, len(packets))
	for i, packet := range packets {
		sizes[i] = float64(packet.Size)
	}

	mean := 0.0
	for _, size := range sizes {
		mean += size
	}
	mean /= float64(len(sizes))

	variance := 0.0
	for _, size := range sizes {
		variance += (size - mean) * (size - mean)
	}
	variance /= float64(len(sizes))
	stdDev := math.Sqrt(variance)

	anomalies := 0
	threshold := 3 * stdDev

	for _, size := range sizes {
		if math.Abs(size-mean) > threshold {
			anomalies++
		}
	}

	return float64(anomalies) / float64(len(sizes))
}

func (di *DetectInjection) analyzeSessionDuration(sessions []*SessionData) float64 {
	if len(sessions) == 0 {
		return 0.0
	}

	totalDuration := 0.0
	for _, session := range sessions {
		totalDuration += float64(session.Duration.Milliseconds())
	}

	avgDuration := totalDuration / float64(len(sessions))

	if avgDuration > 3600000 {
		return 1.0
	}

	return avgDuration / 3600000.0
}

func (di *DetectInjection) analyzeRequestPatterns(sessions []*SessionData) float64 {
	if len(sessions) == 0 {
		return 0.0
	}

	totalRequests := 0
	totalResponses := 0

	for _, session := range sessions {
		totalRequests += session.Requests
		totalResponses += session.Responses
	}

	if totalRequests == 0 {
		return 0.0
	}

	ratio := float64(totalResponses) / float64(totalRequests)

	return math.Abs(1.0 - ratio)
}

func (di *DetectInjection) analyzeErrorPatterns(sessions []*SessionData) float64 {
	if len(sessions) == 0 {
		return 0.0
	}

	totalErrors := 0
	totalRequests := 0

	for _, session := range sessions {
		totalErrors += session.Errors
		totalRequests += session.Requests
	}

	if totalRequests == 0 {
		return 0.0
	}

	errorRate := float64(totalErrors) / float64(totalRequests)

	return math.Min(1.0, errorRate*10.0)
}

func (di *DetectInjection) GetInjectionResults() map[string]*InjectionResult {
	di.mu.RLock()
	defer di.mu.RUnlock()

	results := make(map[string]*InjectionResult)
	for k, v := range di.results {
		results[k] = v
	}
	return results
}

func (di *DetectInjection) GetActiveProfile() string {
	di.mu.RLock()
	profile := "detect_injection"
	di.mu.RUnlock()
	return profile
}

func concatPayloads(packets []*PacketData) []byte {
	var result []byte
	for _, packet := range packets {
		result = append(result, packet.Payload...)
	}
	return result
}

func (di *DetectInjection) verifyPacketHeaders(packet *PacketData, _ *DPIRule) bool {
	if packet.Protocol == "" {
		return false
	}

	for key, value := range packet.Headers {
		if di.isSuspiciousHeader(key, value) {
			return true
		}
	}

	if packet.Size < 64 || packet.Size > 1500 {
		return true
	}

	return false
}

func (di *DetectInjection) isSuspiciousHeader(key, value string) bool {
	suspiciousHeaders := map[string][]string{
		"User-Agent":      {"bot", "crawler", "spider", "scanner"},
		"X-Forwarded-For": {"127.0.0.1", "localhost", "0.0.0.0"},
		"X-Real-IP":       {"127.0.0.1", "localhost"},
		"Connection":      {"close", "keep-alive"},
	}

	if patterns, exists := suspiciousHeaders[key]; exists {
		for _, pattern := range patterns {
			if value != "" && pattern != "" {
				if len(value) >= len(pattern) {
					for i := 0; i <= len(value)-len(pattern); i++ {
						if value[i:i+len(pattern)] == pattern {
							return true
						}
					}
				}
			}
		}
	}

	return false
}

func (di *DetectInjection) calculateSizeFactor(packets []*PacketData) float64 {
	if len(packets) == 0 {
		return 0.0
	}

	sizes := make([]int, len(packets))
	for i, packet := range packets {
		sizes[i] = packet.Size
	}

	mean := 0.0
	for _, size := range sizes {
		mean += float64(size)
	}
	mean /= float64(len(sizes))

	variance := 0.0
	for _, size := range sizes {
		variance += (float64(size) - mean) * (float64(size) - mean)
	}
	variance /= float64(len(sizes))
	stdDev := math.Sqrt(variance)

	return math.Min(1.0, stdDev/1000.0)
}

func (di *DetectInjection) calculateProtocolFactor(packets []*PacketData) float64 {
	if len(packets) == 0 {
		return 0.0
	}

	protocolCounts := make(map[string]int)
	for _, packet := range packets {
		protocolCounts[packet.Protocol]++
	}

	suspiciousProtocols := map[string]float64{
		"TCP":    0.1,
		"UDP":    0.3,
		"ICMP":   0.8,
		"RAW":    0.9,
		"TUNNEL": 0.7,
	}

	totalScore := 0.0
	totalPackets := len(packets)

	for protocol, count := range protocolCounts {
		if weight, exists := suspiciousProtocols[protocol]; exists {
			totalScore += weight * float64(count)
		}
	}

	return totalScore / float64(totalPackets)
}

func (di *DetectInjection) analyzePacketTiming(packets []*PacketData) float64 {
	if len(packets) < 2 {
		return 0.0
	}

	intervals := make([]float64, len(packets)-1)
	for i := 1; i < len(packets); i++ {
		interval := packets[i].Timestamp.Sub(packets[i-1].Timestamp).Seconds()
		intervals[i-1] = interval
	}

	mean := 0.0
	for _, interval := range intervals {
		mean += interval
	}
	mean /= float64(len(intervals))

	variance := 0.0
	for _, interval := range intervals {
		variance += (interval - mean) * (interval - mean)
	}
	variance /= float64(len(intervals))
	stdDev := math.Sqrt(variance)

	if mean == 0 {
		return 0.0
	}

	cv := stdDev / mean
	return math.Min(1.0, cv)
}

func (di *DetectInjection) analyzePayloadEntropy(packets []*PacketData) float64 {
	if len(packets) == 0 {
		return 0.0
	}

	totalEntropy := 0.0
	packetCount := 0

	for _, packet := range packets {
		if len(packet.Payload) > 0 {
			entropy := di.calculateByteEntropy(packet.Payload)
			totalEntropy += entropy
			packetCount++
		}
	}

	if packetCount == 0 {
		return 0.0
	}

	avgEntropy := totalEntropy / float64(packetCount)
	return math.Min(1.0, avgEntropy/8.0)
}

func (di *DetectInjection) calculateByteEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	entropy := 0.0
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / float64(len(data))
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

func (di *DetectInjection) detectProtocolAnomalies(packets []*PacketData) float64 {
	if len(packets) == 0 {
		return 0.0
	}

	anomalyScore := 0.0

	protocolSequence := make([]string, len(packets))
	for i, packet := range packets {
		protocolSequence[i] = packet.Protocol
	}

	unusualTransitions := 0
	for i := 1; i < len(protocolSequence); i++ {
		if di.isUnusualProtocolTransition(protocolSequence[i-1], protocolSequence[i]) {
			unusualTransitions++
		}
	}

	if len(protocolSequence) > 1 {
		anomalyScore = float64(unusualTransitions) / float64(len(protocolSequence)-1)
	}

	return math.Min(1.0, anomalyScore)
}

func (di *DetectInjection) isUnusualProtocolTransition(from, to string) bool {
	unusualTransitions := map[string][]string{
		"TCP":  {"ICMP", "RAW"},
		"UDP":  {"TCP", "ICMP"},
		"ICMP": {"TCP", "UDP"},
		"RAW":  {"TCP", "UDP", "ICMP"},
	}

	if transitions, exists := unusualTransitions[from]; exists {
		for _, transition := range transitions {
			if to == transition {
				return true
			}
		}
	}

	return false
}

func (di *DetectInjection) matchesTLSPattern(payload []byte) bool {
	if len(payload) < 5 {
		return false
	}

	if payload[0] == 0x16 && len(payload) >= 5 {
		if payload[1] == 0x03 && payload[2] == 0x01 {
			return true
		}
	}

	return false
}

func (di *DetectInjection) matchesHTTP2Pattern(payload []byte) bool {
	if len(payload) < 6 {
		return false
	}

	if payload[0] == 0x00 && payload[1] == 0x00 {
		return true
	}

	return false
}

func (di *DetectInjection) matchesWebSocketPattern(payload []byte) bool {
	if len(payload) < 2 {
		return false
	}

	if payload[0] == 0x81 {
		if len(payload) >= 2 {
			return true
		}
	}

	return false
}

func (di *DetectInjection) genericPatternMatch(payload []byte, pattern string) bool {
	patternBytes := []byte(pattern)
	if len(patternBytes) == 0 {
		return false
	}

	for i := 0; i <= len(payload)-len(patternBytes); i++ {
		match := true
		for j := 0; j < len(patternBytes); j++ {
			if payload[i+j] != patternBytes[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}

	return false
}

func (di *DetectInjection) analyzeFlowCharacteristics(flows []*FlowData) float64 {
	if len(flows) == 0 {
		return 0.0
	}

	suspiciousScore := 0.0

	for _, flow := range flows {
		if flow.Bytes > 1000000 {
			suspiciousScore += 0.3
		}

		if flow.Packets > 1000 {
			suspiciousScore += 0.2
		}

		duration := flow.EndTime.Sub(flow.StartTime)
		if duration > 10*time.Minute {
			suspiciousScore += 0.2
		}

		if flow.Protocol == "ICMP" || flow.Protocol == "RAW" {
			suspiciousScore += 0.3
		}
	}

	avgScore := suspiciousScore / float64(len(flows))
	return math.Min(1.0, avgScore)
}

func (di *DetectInjection) analyzeSessionBehavior(sessions []*SessionData) float64 {
	if len(sessions) == 0 {
		return 0.0
	}

	behaviorScore := 0.0

	for _, session := range sessions {
		if session.Requests > 0 {
			responseRatio := float64(session.Responses) / float64(session.Requests)
			if responseRatio < 0.5 || responseRatio > 2.0 {
				behaviorScore += 0.3
			}
		}

		if session.Requests > 0 {
			errorRate := float64(session.Errors) / float64(session.Requests)
			if errorRate > 0.1 {
				behaviorScore += 0.4
			}
		}

		if session.Duration > 30*time.Minute {
			behaviorScore += 0.2
		}

		if di.isSuspiciousUserAgent(session.UserAgent) {
			behaviorScore += 0.3
		}
	}

	avgScore := behaviorScore / float64(len(sessions))
	return math.Min(1.0, avgScore)
}

func (di *DetectInjection) isSuspiciousUserAgent(userAgent string) bool {
	if userAgent == "" {
		return true
	}

	suspiciousPatterns := []string{
		"bot", "crawler", "spider", "scanner", "automated",
		"python", "curl", "wget", "libwww", "lwp",
		"java", "go-http", "okhttp", "apache-httpclient",
	}

	userAgentLower := strings.ToLower(userAgent)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(userAgentLower, pattern) {
			return true
		}
	}

	return false
}
