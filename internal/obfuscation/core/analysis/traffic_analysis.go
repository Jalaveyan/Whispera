package core

import (
	"encoding/csv"
	"fmt"
	"math"
	"os"
	"strconv"
	"time"

	"whispera/internal/util"
)

type TrafficContext struct {
	Direction    string        `json:"direction"`
	Protocol     string        `json:"protocol"`
	Size         int           `json:"size"`
	Timestamp    time.Time     `json:"timestamp"`
	NetworkInfo  *NetworkInfo  `json:"network_info"`
	UserBehavior *UserBehavior `json:"user_behavior"`
	ThreatLevel  int           `json:"threat_level"`
}

type TrafficState struct {
	PacketCount         int
	ByteCount           int64
	Direction           string
	Protocol            string
	LastPacket          time.Time
	Intervals           []time.Duration
	PacketSizes         []int
	RecentPacketSizes   []int
	RecentDPIDetections []bool
	DetectedDPI         bool
	ThreatLevel         int
	MaxHistorySize      int
	LastCleanup         time.Time
	CleanupInterval     time.Duration
}

type NetworkInfo struct {
	RTT        time.Duration `json:"rtt"`
	Bandwidth  int64         `json:"bandwidth"`
	PacketLoss float64       `json:"packet_loss"`
	Jitter     time.Duration `json:"jitter"`
	Congestion int           `json:"congestion"`
}

type UserBehavior struct {
	SessionDuration time.Duration `json:"session_duration"`
	DataVolume      int64         `json:"data_volume"`
	RequestPattern  string        `json:"request_pattern"`
	TimeOfDay       int           `json:"time_of_day"`
	DayOfWeek       int           `json:"day_of_week"`
}

type TrafficAnalysisEngine struct {
	dpiAnalyzer      *DPIAnalyzer
	timingAnalyzer   *TimingAnalyzer
	protocolAnalyzer *ProtocolAnalyzer
	flowAnalyzer     *FlowAnalyzer
	burstAnalyzer    *BurstAnalyzer
	sessionAnalyzer  *SessionAnalyzer
}

type TrafficAnalyzerInterface interface {
	detectDPI(data []byte, context *TrafficContext) (bool, time.Duration)
	AnalyzeUserBehavior() string
	AnalyzeThreatLevel() int
	UpdateNetworkConditions()
	GetContext() *ContextAnalyzer
	GetNetworkConditions() *NetworkAnalyzer
	LoadRealTrafficData(filename string) error
}

type ContextAnalyzer struct {
	UserBehavior string
	ThreatLevel  int
	NetworkInfo  *NetworkInfo
}

type NetworkAnalyzer struct {
	RTT        time.Duration
	Bandwidth  int64
	PacketLoss float64
	Jitter     time.Duration
	Congestion int
}

type DPIAnalyzer struct {
	detectionHistory []bool
	confidenceLevel  float64
}

type TimingAnalyzer struct {
	timingHistory []time.Duration
	patternScore  float64
}

type ProtocolAnalyzer struct {
	signatureHistory []string
	anomalyScore     float64
}

type FlowAnalyzer struct {
	flowHistory  []FlowRecord
	anomalyScore float64
}

type BurstAnalyzer struct {
	burstHistory []BurstRecord
	patternScore float64
}

type SessionAnalyzer struct {
	sessionHistory []SessionRecord
	patternScore   float64
}

func (sa *SessionAnalyzer) GetPatternScore() float64 {
	return sa.patternScore
}

type FlowRecord struct {
	Timestamp   time.Time
	PacketCount int
	ByteCount   int64
	Duration    time.Duration
	Protocol    string
	Direction   string
}

type BurstRecord struct {
	Timestamp    time.Time
	BurstSize    int
	BurstGap     time.Duration
	BurstPattern string
}

type SessionRecord struct {
	StartTime   time.Time
	EndTime     time.Time
	Duration    time.Duration
	PacketCount int
	ByteCount   int64
	Pattern     string
}

func NewTrafficAnalysis() *TrafficAnalysisEngine {
	return &TrafficAnalysisEngine{
		dpiAnalyzer:      &DPIAnalyzer{},
		timingAnalyzer:   &TimingAnalyzer{},
		protocolAnalyzer: &ProtocolAnalyzer{},
		flowAnalyzer:     &FlowAnalyzer{},
		burstAnalyzer:    &BurstAnalyzer{},
		sessionAnalyzer:  &SessionAnalyzer{},
	}
}

func (ta *TrafficAnalysisEngine) AnalyzeDPICharacteristics() float64 {
	dpiScore := 0.0

	if len(ta.dpiAnalyzer.detectionHistory) > 0 {
		detectionCount := 0
		for _, detected := range ta.dpiAnalyzer.detectionHistory {
			if detected {
				detectionCount++
			}
		}
		dpiScore = float64(detectionCount) / float64(len(ta.dpiAnalyzer.detectionHistory))
	}

	dpiScore = (dpiScore + ta.dpiAnalyzer.confidenceLevel) / 2.0

	baseScore := 0.5
	dpiScore = maxFloat(minFloat(dpiScore, 1.0), 0.0)
	dpiScore = (dpiScore + baseScore) / 2.0

	return dpiScore
}

func (ta *TrafficAnalysisEngine) AnalyzeTimingPatterns() float64 {
	timingScore := 0.0

	if len(ta.timingAnalyzer.timingHistory) > 1 {
		variances := make([]float64, len(ta.timingAnalyzer.timingHistory)-1)
		for i := 1; i < len(ta.timingAnalyzer.timingHistory); i++ {
			diff := ta.timingAnalyzer.timingHistory[i] - ta.timingAnalyzer.timingHistory[i-1]
			variances[i-1] = float64(abs(int(diff.Nanoseconds())))
		}

		avgVariance := 0.0
		for _, v := range variances {
			avgVariance += v
		}
		avgVariance /= float64(len(variances))

		timingScore = 1.0 / (1.0 + avgVariance/1000000.0)
	}

	timingScore = (timingScore + ta.timingAnalyzer.patternScore) / 2.0

	return timingScore
}

func (ta *TrafficAnalysisEngine) AnalyzeProtocolSignatures() float64 {
	protocolScore := 0.0

	if len(ta.protocolAnalyzer.signatureHistory) > 0 {
		signatureCount := make(map[string]int)
		for _, sig := range ta.protocolAnalyzer.signatureHistory {
			signatureCount[sig]++
		}

		totalSignatures := len(ta.protocolAnalyzer.signatureHistory)
		uniqueSignatures := len(signatureCount)

		if totalSignatures > 0 {
			protocolScore = float64(uniqueSignatures) / float64(totalSignatures)
		}
	}

	protocolScore = (protocolScore + (1.0 - ta.protocolAnalyzer.anomalyScore)) / 2.0

	return protocolScore
}

func (ta *TrafficAnalysisEngine) AnalyzeFlowAnomalies() float64 {
	flowScore := 0.0

	if len(ta.flowAnalyzer.flowHistory) > 0 {
		totalPackets := 0
		totalBytes := int64(0)

		for _, flow := range ta.flowAnalyzer.flowHistory {
			totalPackets += flow.PacketCount
			totalBytes += flow.ByteCount
		}

		avgPacketsPerFlow := float64(totalPackets) / float64(len(ta.flowAnalyzer.flowHistory))
		avgBytesPerFlow := float64(totalBytes) / float64(len(ta.flowAnalyzer.flowHistory))

		flowScore = 1.0 / (1.0 + math.Abs(avgPacketsPerFlow-100.0)/100.0)
		flowScore = (flowScore + 1.0/(1.0+math.Abs(avgBytesPerFlow-10000.0)/10000.0)) / 2.0
	}

	flowScore = (flowScore + (1.0 - ta.flowAnalyzer.anomalyScore)) / 2.0

	return flowScore
}

func (ta *TrafficAnalysisEngine) AnalyzeBurstPatterns() float64 {
	burstScore := 0.0

	if len(ta.burstAnalyzer.burstHistory) > 0 {
		totalBursts := 0
		totalGap := time.Duration(0)

		for _, burst := range ta.burstAnalyzer.burstHistory {
			totalBursts += burst.BurstSize
			totalGap += burst.BurstGap
		}

		avgBurstSize := float64(totalBursts) / float64(len(ta.burstAnalyzer.burstHistory))
		avgGap := float64(totalGap.Nanoseconds()) / float64(len(ta.burstAnalyzer.burstHistory))

		burstScore = 1.0 / (1.0 + math.Abs(avgBurstSize-50.0)/50.0)
		burstScore = (burstScore + 1.0/(1.0+math.Abs(avgGap-1000000000.0)/1000000000.0)) / 2.0
	}

	burstScore = (burstScore + ta.burstAnalyzer.patternScore) / 2.0

	return burstScore
}

func (ta *TrafficAnalysisEngine) AnalyzeSessionPatterns() time.Duration {
	sessionDuration := time.Duration(0)

	if len(ta.sessionAnalyzer.sessionHistory) > 0 {
		totalDuration := time.Duration(0)
		for _, session := range ta.sessionAnalyzer.sessionHistory {
			totalDuration += session.Duration
		}

		sessionDuration = totalDuration / time.Duration(len(ta.sessionAnalyzer.sessionHistory))
	}

	return sessionDuration
}

func (ta *TrafficAnalysisEngine) LoadRealTrafficData(csvFile string) error {
	file, err := os.Open(csvFile)
	if err != nil {
		return err
	}
	defer util.SafeClose("file", file.Close)

	reader := csv.NewReader(file)

	records, err := reader.ReadAll()
	if err != nil {
		return err
	}

	for i, record := range records {
		if i == 0 {
			continue
		}

		trafficRecord, err := ta.parseTrafficRecordCSV(record)
		if err != nil {
			continue
		}

		ta.addTrafficRecordCSV(trafficRecord)
	}

	return nil
}

func (ta *TrafficAnalysisEngine) parseTrafficRecordCSV(record []string) (*TrafficRecordCSV, error) {
	if len(record) < 5 {
		return nil, fmt.Errorf("invalid record length")
	}

	trafficClass, err := strconv.Atoi(record[0])
	if err != nil {
		return nil, err
	}

	dpiType, err := strconv.Atoi(record[1])
	if err != nil {
		return nil, err
	}

	isAnomaly, err := strconv.Atoi(record[2])
	if err != nil {
		return nil, err
	}

	timestamp, err := strconv.ParseFloat(record[3], 64)
	if err != nil {
		return nil, err
	}

	features := make([]float64, len(record)-4)
	for i := 4; i < len(record); i++ {
		feature, err := strconv.ParseFloat(record[i], 64)
		if err != nil {
			feature = 0.0
		}
		features[i-4] = feature
	}

	return &TrafficRecordCSV{
		TrafficClass: trafficClass,
		DPIType:      dpiType,
		IsAnomaly:    isAnomaly,
		Timestamp:    timestamp,
		Features:     features,
	}, nil
}

func (ta *TrafficAnalysisEngine) addTrafficRecordCSV(record *TrafficRecordCSV) {
	ta.dpiAnalyzer.detectionHistory = append(ta.dpiAnalyzer.detectionHistory, record.DPIType > 0)

	if record.DPIType > 0 {
		ta.dpiAnalyzer.confidenceLevel = (ta.dpiAnalyzer.confidenceLevel + float64(record.DPIType)/10.0) / 2.0
	}

	protocol := ta.determineProtocol(record.Features)
	ta.protocolAnalyzer.signatureHistory = append(ta.protocolAnalyzer.signatureHistory, protocol)

	if record.IsAnomaly > 0 {
		ta.protocolAnalyzer.anomalyScore = (ta.protocolAnalyzer.anomalyScore + 1.0) / 2.0
	}

	flowRecord := &FlowRecord{
		Timestamp:   time.Unix(int64(record.Timestamp), 0),
		PacketCount: int(record.Features[0]),
		ByteCount:   int64(record.Features[1]),
		Duration:    time.Duration(record.Features[2]) * time.Millisecond,
		Protocol:    protocol,
		Direction:   ta.determineDirection(record.Features),
	}
	ta.flowAnalyzer.flowHistory = append(ta.flowAnalyzer.flowHistory, *flowRecord)

	ta.flowAnalyzer.anomalyScore = (ta.flowAnalyzer.anomalyScore + float64(record.IsAnomaly)) / 2.0
}

func (ta *TrafficAnalysisEngine) determineProtocol(features []float64) string {
	if len(features) < 3 {
		return "unknown"
	}

	if features[0] > 1000 {
		return "http"
	} else if features[1] > 500 {
		return "https"
	} else if features[2] > 100 {
		return "tcp"
	}
	return "udp"
}

func (ta *TrafficAnalysisEngine) determineDirection(features []float64) string {
	if len(features) < 4 {
		return "unknown"
	}

	if features[3] > 0.5 {
		return "outbound"
	}
	return "inbound"
}

func (ta *TrafficAnalysisEngine) CalculateAdvancedStats(data []int) (mean, stdDev, skewness, kurtosis float64) {
	if len(data) == 0 {
		return 0, 0, 0, 0
	}

	sum := 0
	for _, value := range data {
		sum += value
	}
	mean = float64(sum) / float64(len(data))

	variance := 0.0
	for _, value := range data {
		diff := float64(value) - mean
		variance += diff * diff
	}
	variance /= float64(len(data))
	stdDev = math.Sqrt(variance)

	skewness = 0.0
	for _, value := range data {
		diff := float64(value) - mean
		skewness += (diff * diff * diff) / (stdDev * stdDev * stdDev)
	}
	skewness /= float64(len(data))

	kurtosis = 0.0
	for _, value := range data {
		diff := float64(value) - mean
		kurtosis += (diff * diff * diff * diff) / (stdDev * stdDev * stdDev * stdDev)
	}
	kurtosis /= float64(len(data))
	kurtosis -= 3.0

	return mean, stdDev, skewness, kurtosis
}

func (ta *TrafficAnalysisEngine) UpdateSizeDistributionWeights(profile *TrafficProfile, recentSizes []int) {
	if len(recentSizes) == 0 {
		return
	}

	newWeights := make([]float64, len(profile.PacketSizes.Weights))

	for _, size := range recentSizes {
		for i, bin := range profile.PacketSizes.Bins {
			if size >= bin && (i == len(profile.PacketSizes.Bins)-1 || size < profile.PacketSizes.Bins[i+1]) {
				newWeights[i]++
				break
			}
		}
	}

	total := 0.0
	for _, weight := range newWeights {
		total += weight
	}

	if total > 0 {
		for i := range newWeights {
			newWeights[i] /= total
		}
	} else {
		for i := range newWeights {
			newWeights[i] = 1.0 / float64(len(newWeights))
		}
	}

	profile.PacketSizes.Weights = newWeights
}

func (ta *TrafficAnalysisEngine) CalculateAdaptiveSensitivity(sessionLength time.Duration) float64 {
	baseSensitivity := 0.5

	if sessionLength < 5*time.Minute {
		return baseSensitivity + 0.3
	} else if sessionLength < 30*time.Minute {
		return baseSensitivity
	}
	return baseSensitivity - 0.2
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func (ta *TrafficAnalysisEngine) detectDPI(data []byte, context *TrafficContext) (bool, time.Duration) {
	start := time.Now()

	state := &TrafficState{
		PacketSizes: []int{len(data)},
		Intervals:   []time.Duration{},
	}
	if len(state.PacketSizes) > 20 {
		recentSizes := state.PacketSizes[len(state.PacketSizes)-20:]

		anomalies := 0
		for _, size := range recentSizes {
			if size < 8 || size > 1500 {
				anomalies++
			}
		}

		anomalyRatio := float64(anomalies) / float64(len(recentSizes))

		dpiScore := ta.analyzeDPICharacteristics(state)

		combinedThreat := anomalyRatio*0.4 + dpiScore*0.6

		if combinedThreat > 0.7 {
			state.DetectedDPI = true
			state.ThreatLevel = 9
			return true, time.Since(start)
		} else if combinedThreat > 0.4 {
			state.DetectedDPI = true
			state.ThreatLevel = 6
			return true, time.Since(start)
		} else if combinedThreat > 0.2 {
			state.DetectedDPI = false
			state.ThreatLevel = 3
			return false, time.Since(start)
		}
		state.DetectedDPI = false
		state.ThreatLevel = 1
		return false, time.Since(start)
	}

	return false, time.Since(start)
}

func (ta *TrafficAnalysisEngine) analyzeDPICharacteristics(state *TrafficState) float64 {
	if len(state.RecentPacketSizes) < 10 {
		return 0.0
	}

	dpiScore := 0.0

	if ta.analyzeTimingPatterns(state) > 0.5 {
		dpiScore += 0.3
	}

	if ta.analyzeProtocolSignatures(state) > 0.5 {
		dpiScore += 0.4
	}

	if ta.analyzeFlowAnomalies(state) > 0.5 {
		dpiScore += 0.3
	}

	if ta.analyzeFragmentationPatterns(state) > 0.5 {
		dpiScore += 0.2
	}

	if ta.analyzeTCPWindowScaling(state) > 0.5 {
		dpiScore += 0.1
	}

	if ta.analyzeHTTPHeaders(state) > 0.5 {
		dpiScore += 0.2
	}

	return dpiScore
}

func (ta *TrafficAnalysisEngine) analyzeTimingPatterns(state *TrafficState) float64 {
	if len(state.Intervals) < 5 {
		return 0.0
	}

	intervals := state.Intervals[len(state.Intervals)-10:]

	var sum time.Duration
	for _, interval := range intervals {
		sum += interval
	}
	mean := sum / time.Duration(len(intervals))

	variance := 0.0
	for _, interval := range intervals {
		diff := float64(interval - mean)
		variance += diff * diff
	}
	variance /= float64(len(intervals))

	if variance < 1000000 {
		return 0.8
	}

	return 0.0
}

func (ta *TrafficAnalysisEngine) analyzeProtocolSignatures(state *TrafficState) float64 {
	if len(state.PacketSizes) > 0 {
		avgSize := 0
		for _, size := range state.PacketSizes {
			avgSize += size
		}
		avgSize /= len(state.PacketSizes)

		if avgSize > 1000 && avgSize < 1200 {
			return 0.6
		}
	}

	return 0.0
}

func (ta *TrafficAnalysisEngine) analyzeFlowAnomalies(state *TrafficState) float64 {
	if len(state.PacketSizes) < 10 {
		return 0.0
	}

	burstCount := 0
	for i := 1; i < len(state.PacketSizes); i++ {
		if state.PacketSizes[i] > state.PacketSizes[i-1]*2 {
			burstCount++
		}
	}

	burstRatio := float64(burstCount) / float64(len(state.PacketSizes)-1)

	if burstRatio > 0.3 {
		return 0.7
	}

	return 0.0
}

func (ta *TrafficAnalysisEngine) analyzeFragmentationPatterns(state *TrafficState) float64 {
	if len(state.PacketSizes) < 5 {
		return 0.0
	}

	smallPackets := 0
	for _, size := range state.PacketSizes {
		if size < 100 {
			smallPackets++
		}
	}

	smallPacketRatio := float64(smallPackets) / float64(len(state.PacketSizes))

	if smallPacketRatio > 0.5 {
		return 0.6
	}

	return 0.0
}

func (ta *TrafficAnalysisEngine) analyzeTCPWindowScaling(state *TrafficState) float64 {
	_ = state.PacketCount
	_ = state.ByteCount

	return 0.0
}

func (ta *TrafficAnalysisEngine) analyzeHTTPHeaders(state *TrafficState) float64 {
	_ = state.PacketCount
	_ = state.ByteCount

	return 0.0
}

func (ta *TrafficAnalysisEngine) AnalyzeUserBehavior() string {
	return "normal"
}

func (ta *TrafficAnalysisEngine) AnalyzeThreatLevel() int {
	return 5
}

func (ta *TrafficAnalysisEngine) UpdateNetworkConditions() {
}

func (ta *TrafficAnalysisEngine) GetContext() *ContextAnalyzer {
	return &ContextAnalyzer{
		UserBehavior: "normal",
		ThreatLevel:  5,
		NetworkInfo:  &NetworkInfo{},
	}
}

func (ta *TrafficAnalysisEngine) GetNetworkConditions() *NetworkAnalyzer {
	return &NetworkAnalyzer{
		RTT:        50 * time.Millisecond,
		Bandwidth:  1000000,
		PacketLoss: 0.0,
		Jitter:     5 * time.Millisecond,
		Congestion: 0,
	}
}
