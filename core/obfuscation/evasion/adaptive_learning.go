package evasion

import (
	"math"
	"time"
	"whispera/core/obfuscation/types"
)

type LearningPattern = types.LearningPattern

type LearningData = types.LearningData

type LearningStats = types.LearningStats

type TrafficState = types.TrafficState

type TrafficProfile = types.TrafficProfile

type AdaptationStrategy = types.AdaptationStrategy

type ProfileChange = types.ProfileChange

type TimingAdjustment = types.TimingAdjustment

type AdaptiveLearningImpl struct {
	learningRate    float64
	adaptationSpeed float64
	patterns        map[string]*LearningPattern
	recentSizes     []int
	recentIntervals []time.Duration
	threatLevel     float64
	sessionStart    time.Time
}

type LearningPatternStats struct {
	UsageCount    int64
	LastUsed      time.Time
	Effectiveness float64
}

func (al *AdaptiveLearningImpl) performAdaptiveLearning() {
	al.learnPacketSizePatterns()
	al.learnTimingPatterns()
	al.learnBehavioralPatterns()
	al.adaptToThreatLevel()
}

func (al *AdaptiveLearningImpl) learnPacketSizePatterns() {
	if len(al.recentSizes) == 0 {
		return
	}

	mean := al.calculateMean(al.recentSizes)
	stdDev := al.calculateStdDev(al.recentSizes, mean)
	min := al.calculateMin(al.recentSizes)
	max := al.calculateMax(al.recentSizes)

	pattern := al.getOrCreatePattern("packet_size")
	pattern.Parameters["mean"] = mean
	pattern.Parameters["std_dev"] = stdDev
	pattern.Parameters["min"] = min
	pattern.Parameters["max"] = max
	pattern.Parameters["count"] = len(al.recentSizes)

	pattern.SuccessRate = al.calculatePatternEffectiveness("packet_size")
}

func (al *AdaptiveLearningImpl) learnTimingPatterns() {
	if len(al.recentIntervals) == 0 {
		return
	}

	meanInterval := al.calculateMeanInterval(al.recentIntervals)
	stdDevInterval := al.calculateStdDevInterval(al.recentIntervals, meanInterval)
	minInterval := al.calculateMinInterval(al.recentIntervals)
	maxInterval := al.calculateMaxInterval(al.recentIntervals)

	pattern := al.getOrCreatePattern("timing")
	pattern.Parameters["mean_interval"] = meanInterval
	pattern.Parameters["std_dev_interval"] = stdDevInterval
	pattern.Parameters["min_interval"] = minInterval
	pattern.Parameters["max_interval"] = maxInterval
	pattern.Parameters["count"] = len(al.recentIntervals)

	pattern.SuccessRate = al.calculatePatternEffectiveness("timing")
}

func (al *AdaptiveLearningImpl) learnBehavioralPatterns() {
	sessionDuration := time.Since(al.sessionStart)
	hour := time.Now().Hour()
	dayOfWeek := int(time.Now().Weekday())

	pattern := al.getOrCreatePattern("behavioral")
	pattern.Parameters["session_duration"] = sessionDuration
	pattern.Parameters["hour"] = hour
	pattern.Parameters["day_of_week"] = dayOfWeek
	pattern.Parameters["threat_level"] = al.threatLevel

	pattern.SuccessRate = al.calculatePatternEffectiveness("behavioral")
}

func (al *AdaptiveLearningImpl) adaptToThreatLevel() {
	if al.threatLevel > 0.7 {
		al.learningRate = math.Min(al.learningRate*1.2, 0.5)
		al.adaptationSpeed = math.Min(al.adaptationSpeed*1.1, 1.0)
	} else if al.threatLevel < 0.3 {
		al.learningRate = math.Max(al.learningRate*0.9, 0.01)
		al.adaptationSpeed = math.Max(al.adaptationSpeed*0.95, 0.1)
	}
}

func (al *AdaptiveLearningImpl) calculateAdvancedStats(data []int) (float64, float64, float64, float64) {
	if len(data) == 0 {
		return 0, 0, 0, 0
	}

	mean := al.calculateMean(data)

	stdDev := al.calculateStdDev(data, mean)

	min := al.calculateMin(data)

	max := al.calculateMax(data)

	return float64(mean), float64(stdDev), float64(min), float64(max)
}

func (al *AdaptiveLearningImpl) updateSizeDistributionWeights(profile *TrafficProfile, recentSizes []int) {
	if len(recentSizes) == 0 {
		return
	}

	mean := al.calculateMean(recentSizes)
	stdDev := al.calculateStdDev(recentSizes, mean)

	if profile.SizeDistribution != nil {
		for i, size := range profile.SizeDistribution.Bins {
			if i < len(profile.SizeWeights) {
				distance := math.Abs(float64(size) - float64(mean))

				if distance < float64(stdDev) {
					profile.SizeWeights[i] = math.Min(profile.SizeWeights[i]*1.1, 1.0)
				} else {
					profile.SizeWeights[i] = math.Max(profile.SizeWeights[i]*0.9, 0.0)
				}
			}
		}
	}
}

func (al *AdaptiveLearningImpl) analyzeBurstPatterns() float64 {
	score := 0.0

	if len(al.recentSizes) > 10 {
		burstCount := 0
		for i := 1; i < len(al.recentSizes); i++ {
			if al.recentSizes[i] > al.recentSizes[i-1]*2 {
				burstCount++
			}
		}
		burstFrequency := float64(burstCount) / float64(len(al.recentSizes))
		score += burstFrequency * 0.4
	}

	if len(al.recentSizes) > 0 {
		mean := al.calculateMean(al.recentSizes)
		largePackets := 0
		for _, size := range al.recentSizes {
			if size > mean*2 {
				largePackets++
			}
		}
		largePacketRatio := float64(largePackets) / float64(len(al.recentSizes))
		score += largePacketRatio * 0.3
	}

	if len(al.recentIntervals) > 5 {
		shortIntervals := 0
		meanInterval := al.calculateMeanInterval(al.recentIntervals)
		for _, interval := range al.recentIntervals {
			if interval < meanInterval/2 {
				shortIntervals++
			}
		}
		shortIntervalRatio := float64(shortIntervals) / float64(len(al.recentIntervals))
		score += shortIntervalRatio * 0.3
	}

	return math.Min(score, 1.0)
}

func (al *AdaptiveLearningImpl) analyzeSessionPatterns() time.Duration {
	_ = time.Since(al.sessionStart)

	hour := time.Now().Hour()
	if hour >= 6 && hour <= 12 {
		return 5 * time.Minute
	} else if hour >= 13 && hour <= 18 {
		return 15 * time.Minute
	} else if hour >= 19 && hour <= 23 {
		return 30 * time.Minute
	}
	return 2 * time.Minute
}

func (al *AdaptiveLearningImpl) calculateAdaptiveSensitivity(sessionLength time.Duration) float64 {
	baseSensitivity := 0.5

	if sessionLength > 20*time.Minute {
		return math.Min(baseSensitivity*1.5, 1.0)
	} else if sessionLength < 5*time.Minute {
		return math.Max(baseSensitivity*0.5, 0.1)
	}

	if al.threatLevel > 0.7 {
		return math.Min(baseSensitivity*1.3, 1.0)
	} else if al.threatLevel < 0.3 {
		return math.Max(baseSensitivity*0.7, 0.1)
	}

	return baseSensitivity
}

func (al *AdaptiveLearningImpl) calculateMean(values []int) int {
	if len(values) == 0 {
		return 0
	}

	sum := 0
	for _, value := range values {
		sum += value
	}

	return sum / len(values)
}

func (al *AdaptiveLearningImpl) calculateStdDev(values []int, mean int) int {
	if len(values) == 0 {
		return 0
	}

	sum := 0
	for _, value := range values {
		diff := value - mean
		sum += diff * diff
	}

	return int(math.Sqrt(float64(sum) / float64(len(values))))
}

func (al *AdaptiveLearningImpl) calculateMin(values []int) int {
	if len(values) == 0 {
		return 0
	}

	min := values[0]
	for _, value := range values {
		if value < min {
			min = value
		}
	}

	return min
}

func (al *AdaptiveLearningImpl) calculateMax(values []int) int {
	if len(values) == 0 {
		return 0
	}

	max := values[0]
	for _, value := range values {
		if value > max {
			max = value
		}
	}

	return max
}

func (al *AdaptiveLearningImpl) calculateMeanInterval(intervals []time.Duration) time.Duration {
	if len(intervals) == 0 {
		return 0
	}

	var sum time.Duration
	for _, interval := range intervals {
		sum += interval
	}

	return sum / time.Duration(len(intervals))
}

func (al *AdaptiveLearningImpl) calculateStdDevInterval(intervals []time.Duration, mean time.Duration) time.Duration {
	if len(intervals) == 0 {
		return 0
	}

	var sum float64
	for _, interval := range intervals {
		diff := float64(interval - mean)
		sum += diff * diff
	}

	return time.Duration(math.Sqrt(sum / float64(len(intervals))))
}

func (al *AdaptiveLearningImpl) calculateMinInterval(intervals []time.Duration) time.Duration {
	if len(intervals) == 0 {
		return 0
	}

	min := intervals[0]
	for _, interval := range intervals {
		if interval < min {
			min = interval
		}
	}

	return min
}

func (al *AdaptiveLearningImpl) calculateMaxInterval(intervals []time.Duration) time.Duration {
	if len(intervals) == 0 {
		return 0
	}

	max := intervals[0]
	for _, interval := range intervals {
		if interval > max {
			max = interval
		}
	}

	return max
}

func (al *AdaptiveLearningImpl) getOrCreatePattern(name string) *LearningPattern {
	pattern, exists := al.patterns[name]
	if !exists {
		pattern = &LearningPattern{
			Name:        name,
			Frequency:   0.5,
			SuccessRate: 0.5,
			UsageCount:  0,
			LastUsed:    time.Now(),
			Parameters:  make(map[string]interface{}),
		}
		al.patterns[name] = pattern
	}

	pattern.UsageCount++
	pattern.LastUsed = time.Now()

	return pattern
}

func (al *AdaptiveLearningImpl) calculatePatternEffectiveness(patternName string) float64 {
	pattern, exists := al.patterns[patternName]
	if !exists {
		return 0.0
	}

	effectiveness := 0.5

	if pattern.UsageCount > 10 {
		effectiveness += 0.2
	}

	timeSinceLastUse := time.Since(pattern.LastUsed)
	if timeSinceLastUse < 5*time.Minute {
		effectiveness += 0.1
	}

	if al.threatLevel > 0.7 {
		effectiveness += 0.2
	}

	return math.Min(effectiveness, 1.0)
}

func (al *AdaptiveLearningImpl) AddRecentSize(size int) {
	al.recentSizes = append(al.recentSizes, size)

	maxRecent := 100
	if len(al.recentSizes) > maxRecent {
		al.recentSizes = al.recentSizes[len(al.recentSizes)-maxRecent:]
	}
}

func (al *AdaptiveLearningImpl) AddRecentInterval(interval time.Duration) {
	al.recentIntervals = append(al.recentIntervals, interval)

	maxRecent := 100
	if len(al.recentIntervals) > maxRecent {
		al.recentIntervals = al.recentIntervals[len(al.recentIntervals)-maxRecent:]
	}
}

func (al *AdaptiveLearningImpl) SetThreatLevel(level float64) {
	al.threatLevel = math.Max(0.0, math.Min(level, 1.0))
}

func (al *AdaptiveLearningImpl) GetThreatLevel() float64 {
	return al.threatLevel
}

func (al *AdaptiveLearningImpl) GetLearningRate() float64 {
	return al.learningRate
}

func (al *AdaptiveLearningImpl) SetLearningRate(rate float64) {
	al.learningRate = math.Max(0.01, math.Min(rate, 1.0))
}

func (al *AdaptiveLearningImpl) GetAdaptationSpeed() float64 {
	return al.adaptationSpeed
}

func (al *AdaptiveLearningImpl) SetAdaptationSpeed(speed float64) {
	al.adaptationSpeed = math.Max(0.1, math.Min(speed, 1.0))
}

func (al *AdaptiveLearningImpl) GetPatterns() map[string]*LearningPattern {
	return al.patterns
}

func (al *AdaptiveLearningImpl) GetPattern(name string) *LearningPattern {
	return al.patterns[name]
}

func (al *AdaptiveLearningImpl) ResetPatterns() {
	al.patterns = make(map[string]*LearningPattern)
	al.recentSizes = make([]int, 0)
	al.recentIntervals = make([]time.Duration, 0)
	al.sessionStart = time.Now()
}

func (al *AdaptiveLearningImpl) GetSessionDuration() time.Duration {
	return time.Since(al.sessionStart)
}

func (al *AdaptiveLearningImpl) ResetSession() {
	al.sessionStart = time.Now()
	al.recentSizes = make([]int, 0)
	al.recentIntervals = make([]time.Duration, 0)
}

func (al *AdaptiveLearningImpl) LearnFromTraffic(data []byte, success bool, context *types.TrafficContext) error {
	al.AddRecentSize(len(data))

	if success {
		al.threatLevel = math.Max(0.0, al.threatLevel-0.1)
	} else {
		al.threatLevel = math.Min(1.0, al.threatLevel+0.1)
	}

	al.performAdaptiveLearning()

	mean, stdDev, min, max := al.calculateAdvancedStats(al.recentSizes)
	_ = mean
	_ = stdDev
	_ = min
	_ = max

	burstScore := al.analyzeBurstPatterns()
	_ = burstScore

	sessionDuration := al.analyzeSessionPatterns()
	_ = sessionDuration

	sensitivity := al.calculateAdaptiveSensitivity(sessionDuration)
	_ = sensitivity

	return nil
}

func (al *AdaptiveLearningImpl) GetAdaptationStrategy() *AdaptationStrategy {
	return &AdaptationStrategy{
		ProfileChanges:    []*ProfileChange{},
		TimingAdjustments: []*TimingAdjustment{},
		Priority:          1,
		Confidence:        al.calculatePatternEffectiveness("behavioral"),
	}
}

func (al *AdaptiveLearningImpl) UpdateEffectiveness(profile string, success bool) error {
	pattern := al.getOrCreatePattern(profile)
	if success {
		pattern.SuccessRate = math.Min(1.0, pattern.SuccessRate+0.1)
	} else {
		pattern.SuccessRate = math.Max(0.0, pattern.SuccessRate-0.05)
	}

	trafficProfile := &TrafficProfile{
		Name: profile,
	}
	al.updateSizeDistributionWeights(trafficProfile, al.recentSizes)

	return nil
}

func (al *AdaptiveLearningImpl) GetLearningData() *types.LearningData {
	patterns := make(map[string]*LearningPattern)
	for name, pattern := range al.patterns {
		patterns[name] = pattern
	}

	effectiveness := make(map[string]float64)
	for name, pattern := range al.patterns {
		effectiveness[name] = pattern.SuccessRate
	}

	return &types.LearningData{
		Patterns:      patterns,
		Effectiveness: effectiveness,
		LastUpdate:    time.Now(),
	}
}

func (al *AdaptiveLearningImpl) SetLearningData(data *types.LearningData) {
	if data == nil {
		return
	}

	for name, pattern := range data.Patterns {
		al.patterns[name] = pattern
	}

	for name, eff := range data.Effectiveness {
		if pattern, exists := al.patterns[name]; exists {
			pattern.SuccessRate = eff
		}
	}
}

func (al *AdaptiveLearningImpl) GetLearningStats() *types.LearningStats {
	totalSamples := int64(len(al.recentSizes) + len(al.recentIntervals))
	successCount := int64(0)
	failureCount := int64(0)

	for _, pattern := range al.patterns {
		if pattern.SuccessRate > 0.5 {
			successCount += pattern.UsageCount
		} else {
			failureCount += pattern.UsageCount
		}
	}

	averageAccuracy := 0.0
	if totalSamples > 0 {
		averageAccuracy = float64(successCount) / float64(totalSamples)
	}

	return &types.LearningStats{
		TotalSamples:    totalSamples,
		SuccessCount:    successCount,
		FailureCount:    failureCount,
		AverageAccuracy: averageAccuracy,
		LastUpdate:      time.Now(),
		LearningRate:    al.learningRate,
		AdaptationCount: int64(len(al.patterns)),
	}
}

func (al *AdaptiveLearningImpl) ResetLearning() error {
	al.ResetPatterns()
	al.learningRate = 0.1
	al.adaptationSpeed = 0.5
	al.threatLevel = 0.5
	return nil
}
