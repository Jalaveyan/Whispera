package marionette

import (
	"encoding/csv"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"whispera/internal/util"
)

var _ = []interface{}{
	(*Marionette).analyzeTrafficSuccess,
	(*Marionette).loadRealTrafficData,
	(*Marionette).enableFallbackMode,
}

func (m *Marionette) detectDPI() float64 {
	threat := 0.0
	threat += m.analyzeFragmentationPatterns()
	threat += m.analyzeTCPWindowScaling()
	threat += m.analyzeHTTPHeaders()

	m.Mutex.Lock()
	m.State.ThreatLevel = int(threat * 10)
	m.Mutex.Unlock()
	return threat
}

func (m *Marionette) analyzeFragmentationPatterns() float64 {
	if len(m.State.Intervals) < 5 {
		return 0.0
	}
	score := 0.0
	for i := 1; i < len(m.State.PacketSizes); i++ {
		diff := abs(m.State.PacketSizes[i] - m.State.PacketSizes[i-1])
		if diff > 1000 {
			score += 0.2
		}
	}
	return score
}

func (m *Marionette) analyzeTCPWindowScaling() float64 {
	if len(m.State.PacketSizes) > 3 {
		avg := 0
		for _, s := range m.State.PacketSizes {
			avg += s
		}
		if avg/len(m.State.PacketSizes) > 1500 {
			return 0.3
		}
	}
	return 0.0
}

func (m *Marionette) analyzeHTTPHeaders() float64 {
	score := 0.0
	for _, size := range m.State.PacketSizes {
		if size > 100 && size < 200 {
			score += 0.1
		}
	}
	return score
}

func (m *Marionette) generateCoverTraffic() []byte {
	if len(m.CoverTraffic) > 0 {
		return m.CoverTraffic
	}
	size := m.generateRealisticRandom(128) + 32
	data := make([]byte, size)
	switch m.Active {
	case "vk":
		for i := range data {
			data[i] = byte((i*13 + size*7) % 256)
		}
	case "yandex":
		for i := range data {
			data[i] = byte((i*17 + size*11) % 256)
		}
	default:
		for i := range data {
			data[i] = byte(m.generateRealisticRandom(256))
		}
	}
	m.CoverTraffic = data
	return data
}

func (m *Marionette) ApplyProductionDPIEvasion(data []byte, service string) ([]byte, time.Duration, error) {
	processor := func(d []byte) ([]byte, error) {
		var res []byte
		var err error
		var dur time.Duration

		switch service {
		case "vk":
			res, dur, err = m.applyProductionVKontakteEvasion(d)
		case "yandex":
			res, dur, err = m.applyProductionYandexEvasion(d)
		case "mailru":
			res, dur, err = m.applyProductionMailruEvasion(d)
		case "rutube":
			res, dur, err = m.applyProductionRutubeEvasion(d)
		case "ozon":
			res, dur, err = m.applyProductionOzonEvasion(d)
		default:
			res, dur, err = m.applyProductionGenericRussianEvasion(d)
		}

		if dur > 0 {
		}

		return res, err
	}

	processed, err := m.processWithTimeout(data, processor, 200*time.Millisecond)
	if err != nil {
		return data, 0, err
	}

	return processed, 0, nil
}

func (m *Marionette) analyzeTrafficSuccess(data []byte, _ string) bool {
	if len(data) < 8 || len(data) > 65535 {
		return false
	}
	if m.detectSuspiciousPatterns(data) {
		return false
	}
	return m.calculatePacketEntropy(data) >= 3.0
}

func (m *Marionette) detectSuspiciousPatterns(data []byte) bool {
	rep := 0
	for i := 1; i < len(data); i++ {
		if data[i] == data[i-1] {
			rep++
		}
	}
	return float64(rep)/float64(len(data)) > 0.3
}

func (m *Marionette) calculatePacketEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	f := make(map[byte]int)
	for _, b := range data {
		f[b]++
	}
	e, dl := 0.0, float64(len(data))
	for _, c := range f {
		p := float64(c) / dl
		e -= p * math.Log2(p)
	}
	return e
}

func (m *Marionette) getCoverTrafficSize() int {
	m.Mutex.RLock()
	defer m.Mutex.RUnlock()
	return len(m.CoverTraffic)
}

func (m *Marionette) clearCoverTraffic() {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	m.CoverTraffic = nil
}

func (m *Marionette) calculateAdvancedStats(data []int) (float64, float64, float64, float64) {
	if len(data) == 0 {
		return 0, 0, 0, 0
	}

	sum := 0
	for _, v := range data {
		sum += v
	}
	mean := float64(sum) / float64(len(data))

	var variance float64
	for _, v := range data {
		diff := float64(v) - mean
		variance += diff * diff
	}
	variance /= float64(len(data))
	stdDev := math.Sqrt(variance)

	var skewness, kurtosis float64
	for _, v := range data {
		diff := (float64(v) - mean) / stdDev
		skewness += diff * diff * diff
		kurtosis += diff * diff * diff * diff
	}
	skewness /= float64(len(data))
	kurtosis = (kurtosis / float64(len(data))) - 3

	return mean, stdDev, skewness, kurtosis
}

func (m *Marionette) calculateStdDev(data []int) float64 {
	if len(data) == 0 {
		return 0
	}
	sum := 0
	for _, v := range data {
		sum += v
	}
	mean := float64(sum) / float64(len(data))
	var variance float64
	for _, v := range data {
		diff := float64(v) - mean
		variance += diff * diff
	}
	variance /= float64(len(data))
	return math.Sqrt(variance)
}

func (m *Marionette) calculateMean(values []int) int {
	if len(values) == 0 {
		return 0
	}
	sum := 0
	for _, v := range values {
		sum += v
	}
	return sum / len(values)
}

func (m *Marionette) calculateMin(values []int) int {
	if len(values) == 0 {
		return 0
	}
	min := values[0]
	for _, v := range values {
		if v < min {
			min = v
		}
	}
	return min
}

func (m *Marionette) calculateMax(values []int) int {
	if len(values) == 0 {
		return 0
	}
	max := values[0]
	for _, v := range values {
		if v > max {
			max = v
		}
	}
	return max
}

type TrafficRecordCSV struct {
	TrafficClass int       `json:"traffic_class"`
	DPIType      int       `json:"dpi_type"`
	IsAnomaly    int       `json:"is_anomaly"`
	Timestamp    float64   `json:"timestamp"`
	Features     []float64 `json:"features"`
}

type TrafficAnalysis struct {
	TotalRecords int
	PacketSizes  []int
	Intervals    []time.Duration
	Features     [][]float64
}

func (m *Marionette) loadRealTrafficData(csvFile string) {
	records, err := m.parseTrafficCSV(csvFile)
	if err != nil {
		fmt.Printf("Warning: Failed to load traffic data from %s: %v\n", csvFile, err)
		return
	}
	analysis := m.analyzeRealTraffic(records)
	m.updateProfilesFromRealData(analysis)
}

func (m *Marionette) parseTrafficCSV(filename string) ([]TrafficRecordCSV, error) {
	if strings.Contains(filename, "..") {
		return nil, fmt.Errorf("invalid filename")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open CSV file: %v", err)
	}
	defer util.SafeClose("file", file.Close)

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV: %v", err)
	}
	if len(records) < 2 {
		return nil, fmt.Errorf("CSV file is empty")
	}

	trafficRecords := make([]TrafficRecordCSV, 0, len(records)-1)
	for _, row := range records[1:] {
		if len(row) < 5 {
			continue
		}
		tc, _ := strconv.Atoi(row[0])
		dt, _ := strconv.Atoi(row[1])
		ia, _ := strconv.Atoi(row[2])
		ts, _ := strconv.ParseFloat(row[3], 64)
		features, err := m.parseFeatures(row[4])
		if err != nil {
			continue
		}
		trafficRecords = append(trafficRecords, TrafficRecordCSV{TrafficClass: tc, DPIType: dt, IsAnomaly: ia, Timestamp: ts, Features: features})
	}
	return trafficRecords, nil
}

func (m *Marionette) parseFeatures(featuresStr string) ([]float64, error) {
	featuresStr = strings.Trim(featuresStr, "[]\"")
	parts := strings.Split(featuresStr, ",")
	features := make([]float64, 0, len(parts))
	for _, part := range parts {
		if val, err := strconv.ParseFloat(strings.TrimSpace(part), 64); err == nil {
			features = append(features, val)
		}
	}
	return features, nil
}

func (m *Marionette) analyzeRealTraffic(records []TrafficRecordCSV) *TrafficAnalysis {
	analysis := &TrafficAnalysis{TotalRecords: len(records)}
	for _, r := range records {
		if len(r.Features) > 0 {
			analysis.PacketSizes = append(analysis.PacketSizes, int(r.Features[0]*1000))
		}
		analysis.Features = append(analysis.Features, r.Features)
	}
	return analysis
}

func (m *Marionette) updateProfilesFromRealData(analysis *TrafficAnalysis) {
	if len(analysis.PacketSizes) == 0 {
		return
	}
	mean := m.calculateMean(analysis.PacketSizes)
	std := m.calculateStdDev(analysis.PacketSizes)
	min, max := m.calculateMin(analysis.PacketSizes), m.calculateMax(analysis.PacketSizes)

	if p, ok := m.Profiles["vk"]; ok {
		p.PacketSizes.Mean = float64(mean)
		p.PacketSizes.StdDev = float64(std)
		p.PacketSizes.Min = min
		p.PacketSizes.Max = max
	}
}

type EffectivenessMetrics struct {
	TotalPackets         int64
	SuccessfulEvasion    int64
	FailedEvasion        int64
	FalsePositives       int64
	AverageLatency       time.Duration
	Throughput           float64
	ProfileEffectiveness map[string]float64
	LastReset            time.Time
}

func NewEffectivenessMetrics() *EffectivenessMetrics {
	return &EffectivenessMetrics{
		ProfileEffectiveness: make(map[string]float64),
		LastReset:            util.GetGlobalTimeCache().Now(),
	}
}

func (em *EffectivenessMetrics) RecordPacketResult(success bool, latency time.Duration, profile string) {
	em.TotalPackets++
	if success {
		em.SuccessfulEvasion++
	} else {
		em.FailedEvasion++
	}
	if em.AverageLatency == 0 {
		em.AverageLatency = latency
	} else {
		em.AverageLatency = (em.AverageLatency + latency) / 2
	}
	if _, exists := em.ProfileEffectiveness[profile]; !exists {
		em.ProfileEffectiveness[profile] = 0.0
	}
	rate := 0.0
	if success {
		rate = 0.1
	}
	em.ProfileEffectiveness[profile] = (em.ProfileEffectiveness[profile] * 0.9) + rate
}

func (em *EffectivenessMetrics) GetEffectivenessReport() map[string]interface{} {
	sr, fr := 0.0, 0.0
	if em.TotalPackets > 0 {
		sr = float64(em.SuccessfulEvasion) / float64(em.TotalPackets) * 100.0
		fr = float64(em.FailedEvasion) / float64(em.TotalPackets) * 100.0
	}
	bestProfile, bestRate := "", 0.0
	for p, r := range em.ProfileEffectiveness {
		if r > bestRate {
			bestRate = r
			bestProfile = p
		}
	}
	return map[string]interface{}{
		"total_packets": em.TotalPackets, "success_rate": sr, "failure_rate": fr,
		"average_latency": em.AverageLatency.String(), "best_profile": bestProfile,
		"uptime": time.Since(em.LastReset).String(),
	}
}

func (em *EffectivenessMetrics) ResetMetrics() {
	em.TotalPackets = 0
	em.SuccessfulEvasion = 0
	em.FailedEvasion = 0
	em.AverageLatency = 0
	em.ProfileEffectiveness = make(map[string]float64)
	em.LastReset = util.GetGlobalTimeCache().Now()
}

func (m *Marionette) getPerformanceMetrics() *SystemMetrics {
	m.Mutex.RLock()
	defer m.Mutex.RUnlock()
	m.Metrics.MemoryUsage = int64(len(m.State.PacketSizes) + len(m.State.Intervals) + len(m.State.RecentPacketSizes) + len(m.State.RecentDPIDetections))
	return m.Metrics
}

func (m *Marionette) enableFallbackMode() {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	m.FallbackMode = true
}

func (m *Marionette) disableFallbackMode() {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	m.FallbackMode = false
}

func (m *Marionette) isFallbackMode() bool {
	m.Mutex.RLock()
	defer m.Mutex.RUnlock()
	return m.FallbackMode
}

func (m *Marionette) GetSystemMetrics() *SystemMetrics { return m.getPerformanceMetrics() }
func (m *Marionette) ResetFallbackMode()               { m.disableFallbackMode() }

func (m *Marionette) HealthCheck() map[string]interface{} {
	metrics := m.getPerformanceMetrics()
	health := map[string]interface{}{
		"status": "healthy", "fallback_mode": m.isFallbackMode(), "circuit_breaker": m.CircuitBreaker.State,
		"packets_processed": metrics.PacketsProcessed, "ml_predictions": metrics.MLPredictions,
		"ml_failures": metrics.MLFailures, "memory_usage": metrics.MemoryUsage, "average_latency": metrics.AverageLatency.String(),
	}
	if metrics.MLFailures > metrics.MLPredictions/2 {
		health["status"] = "degraded"
	}
	if m.isFallbackMode() {
		health["status"] = "fallback"
	}
	return health
}
