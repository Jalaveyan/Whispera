package evasion

import (
	"fmt"
	"math"
	"sync"
	"time"
	"whispera/neural/types"
)

const profileTypeProtocol = "protocol"

type AdaptiveProfileManagerImpl struct {
	profiles            map[string]*types.AdaptiveProfile
	recommendations     map[string]*types.ProfileRecommendation
	feedback            map[string]*types.AdaptationFeedback
	mutex               sync.RWMutex
	learningRate        float64
	adaptationThreshold float64
}

func (apm *AdaptiveProfileManagerImpl) SelectOptimalProfile(context *types.TrafficContext) (string, error) {
	apm.mutex.RLock()
	defer apm.mutex.RUnlock()

	if len(apm.profiles) == 0 {
		return "", fmt.Errorf("no profiles available")
	}

	var bestProfile string
	bestScore := -1.0

	for name, profile := range apm.profiles {
		score := apm.calculateProfileScore(profile, context)
		if score > bestScore {
			bestScore = score
			bestProfile = name
		}
	}

	return bestProfile, nil
}

func (apm *AdaptiveProfileManagerImpl) AdaptProfile(profileName string, feedback *types.AdaptationFeedback) error {
	apm.mutex.Lock()
	defer apm.mutex.Unlock()

	profile, ok := apm.profiles[profileName]
	if !ok {
		return fmt.Errorf("profile %s not found", profileName)
	}

	if feedback.Success {
		profile.Effectiveness = profile.Effectiveness*(1-apm.learningRate) + 1.0*apm.learningRate
		profile.SuccessRate = profile.SuccessRate*(1-apm.learningRate) + 1.0*apm.learningRate
	} else {
		profile.Effectiveness = profile.Effectiveness*(1-apm.learningRate) + 0.0*apm.learningRate
		profile.SuccessRate = profile.SuccessRate*(1-apm.learningRate) + 0.0*apm.learningRate
	}

	profile.AverageLatency = time.Duration(float64(profile.AverageLatency)*(1-apm.learningRate) + float64(feedback.Latency)*apm.learningRate)
	profile.LastAdaptation = time.Now()
	profile.AdaptationCount++

	apm.feedback[profileName] = feedback

	if profile.SuccessRate < apm.adaptationThreshold {
		apm.adaptProfileParameters(profile, feedback)
	}

	return nil
}

func (apm *AdaptiveProfileManagerImpl) GetProfileRecommendations(
	context *types.TrafficContext,
) []*types.ProfileRecommendation {
	apm.mutex.RLock()
	defer apm.mutex.RUnlock()

	var recommendations []*types.ProfileRecommendation

	for name, profile := range apm.profiles {
		score := apm.calculateProfileScore(profile, context)
		if score > 0.5 {
			recommendations = append(recommendations, &types.ProfileRecommendation{
				ProfileName: name,
				Confidence:  score,
				Reason:      apm.getRecommendationReason(profile, context),
				Priority:    int(score * 10),
			})
		}
	}

	return recommendations
}

func (apm *AdaptiveProfileManagerImpl) calculateProfileScore(
	profile *types.AdaptiveProfile, context *types.TrafficContext,
) float64 {
	score := 0.0

	score += apm.calculateTypeScore(profile, context)

	score += profile.Effectiveness * 0.4

	score += apm.calculateConfidence(profile, context) * 0.2

	return math.Min(1.0, score)
}

func (apm *AdaptiveProfileManagerImpl) calculateTypeScore(
	profile *types.AdaptiveProfile, context *types.TrafficContext,
) float64 {
	switch profile.Type {
	case profileTypeProtocol:
		if profile.Parameters["protocol"] == context.Protocol {
			return 0.4
		}
	case "direction":
		if profile.Parameters["direction"] == context.Direction {
			return 0.3
		}
	}
	return 0.1
}

func (apm *AdaptiveProfileManagerImpl) calculateConfidence(
	profile *types.AdaptiveProfile, context *types.TrafficContext,
) float64 {
	if context.Direction != "" || context.Protocol != "" {
		return 0.5
	}

	if profile.UsageCount > 100 {
		return 0.8
	} else if profile.UsageCount > 10 {
		return 0.5
	}
	return 0.2
}

func (apm *AdaptiveProfileManagerImpl) getRecommendationReason(
	profile *types.AdaptiveProfile, context *types.TrafficContext,
) string {
	if profile.SuccessRate > 0.9 {
		return "high_success_rate"
	}
	if profile.Type == profileTypeProtocol && profile.Parameters["protocol"] == context.Protocol {
		return "protocol_match"
	}
	return "general_suitability"
}

func (apm *AdaptiveProfileManagerImpl) adaptProfileParameters(
	profile *types.AdaptiveProfile, feedback *types.AdaptationFeedback,
) {
	if profile.Parameters == nil {
		profile.Parameters = make(map[string]interface{})
	}

	apm.adaptAggressiveness(profile, feedback.Success)

	apm.adaptDelayFactor(profile, feedback.Latency)
}

func (apm *AdaptiveProfileManagerImpl) adaptAggressiveness(profile *types.AdaptiveProfile, success bool) {
	val, exists := profile.Parameters["aggressiveness"]
	if !exists {
		if success {
			profile.Parameters["aggressiveness"] = 0.5
		} else {
			profile.Parameters["aggressiveness"] = 0.7
		}
		return
	}

	if agg, ok := val.(float64); ok {
		if success {
			profile.Parameters["aggressiveness"] = math.Max(0.1, agg-0.05)
		} else {
			profile.Parameters["aggressiveness"] = math.Min(1.0, agg+0.1)
		}
	}
}

func (apm *AdaptiveProfileManagerImpl) adaptDelayFactor(profile *types.AdaptiveProfile, latency time.Duration) {
	if latency <= 0 {
		return
	}

	val, exists := profile.Parameters["delay_factor"]
	if !exists {
		profile.Parameters["delay_factor"] = 1.0
		return
	}

	if delay, ok := val.(float64); ok {
		if latency < 50*time.Millisecond {
			profile.Parameters["delay_factor"] = math.Max(0.5, delay-0.1)
		} else if latency > 200*time.Millisecond {
			profile.Parameters["delay_factor"] = math.Min(3.0, delay+0.2)
		}
	}
}

func (apm *AdaptiveProfileManagerImpl) AddProfile(name string, profile *types.AdaptiveProfile) {
	apm.mutex.Lock()
	defer apm.mutex.Unlock()

	if apm.profiles == nil {
		apm.profiles = make(map[string]*types.AdaptiveProfile)
	}
	apm.profiles[name] = profile
}

func (apm *AdaptiveProfileManagerImpl) GetProfile(name string) (*types.AdaptiveProfile, bool) {
	apm.mutex.RLock()
	defer apm.mutex.RUnlock()

	if apm.profiles == nil {
		return nil, false
	}
	profile, ok := apm.profiles[name]
	return profile, ok
}

func (apm *AdaptiveProfileManagerImpl) GetProfileStats() map[string]*AdaptiveProfileStats {
	apm.mutex.RLock()
	defer apm.mutex.RUnlock()

	stats := make(map[string]*AdaptiveProfileStats)
	for name, profile := range apm.profiles {
		stats[name] = &AdaptiveProfileStats{
			Name:            name,
			Type:            profile.Type,
			Effectiveness:   profile.Effectiveness,
			SuccessRate:     profile.SuccessRate,
			AverageLatency:  profile.AverageLatency,
			UsageCount:      profile.UsageCount,
			LastUsed:        profile.LastUsed,
			LastAdaptation:  profile.LastAdaptation,
			AdaptationCount: profile.AdaptationCount,
		}
	}
	return stats
}

func (apm *AdaptiveProfileManagerImpl) SetLearningRate(rate float64) {
	apm.mutex.Lock()
	defer apm.mutex.Unlock()

	apm.learningRate = rate
}

func (apm *AdaptiveProfileManagerImpl) SetAdaptationThreshold(threshold float64) {
	apm.mutex.Lock()
	defer apm.mutex.Unlock()

	apm.adaptationThreshold = threshold
}

type AdaptiveProfileStats struct {
	Name            string        `json:"name"`
	Type            string        `json:"type"`
	Effectiveness   float64       `json:"effectiveness"`
	SuccessRate     float64       `json:"success_rate"`
	AverageLatency  time.Duration `json:"average_latency"`
	UsageCount      int64         `json:"usage_count"`
	LastUsed        time.Time     `json:"last_used"`
	LastAdaptation  time.Time     `json:"last_adaptation"`
	AdaptationCount int64         `json:"adaptation_count"`
}

func (apm *AdaptiveProfileManagerImpl) LearnFromTraffic(data []byte, profileName string, success bool) {
	apm.mutex.Lock()
	defer apm.mutex.Unlock()

	profile, ok := apm.profiles[profileName]
	if !ok {
		return
	}

	profile.UsageCount++
	profile.LastUsed = time.Now()

	if success {
		profile.SuccessRate = profile.SuccessRate*(1-apm.learningRate) + 1.0*apm.learningRate
	} else {
		profile.SuccessRate = profile.SuccessRate*(1-apm.learningRate) + 0.0*apm.learningRate
	}
}
