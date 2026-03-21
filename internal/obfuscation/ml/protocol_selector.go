package ml

import (
	"sync"
	"time"

	"whispera/internal/obfuscation/core/types"
)

type ProtocolRecommendation struct {
	Protocol              string
	Confidence            float64
	Reason                string
	ExpectedEffectiveness float64
	ThreatLevel           int
}

type ProtocolSelector struct {
	mlSystem        *UnifiedMLSystem
	recommendations map[string]*ProtocolRecommendation
	lastAnalysis    time.Time
	mu              sync.RWMutex
	history         []ProtocolRecommendation
	maxHistory      int
}

func NewProtocolSelector(mlSystem *UnifiedMLSystem) *ProtocolSelector {
	return &ProtocolSelector{
		mlSystem:        mlSystem,
		recommendations: make(map[string]*ProtocolRecommendation),
		maxHistory:      100,
	}
}

func (ps *ProtocolSelector) SelectProtocol(networkConditions *NetworkConditions) (*ProtocolRecommendation, error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if ps.mlSystem == nil {
		return ps.getDefaultRecommendation(networkConditions), nil
	}

	testPacket := ps.createTestPacket(networkConditions)

	var response *types.MLPredictionResponse
	var err error

	if ps.mlSystem != nil && ps.mlSystem.engine != nil {
		response = ps.mlSystem.engine.Predict(testPacket, "protocol_selection", "outbound")
		if response == nil {
			return ps.getDefaultRecommendation(networkConditions), nil
		}
	} else {
		return ps.getDefaultRecommendation(networkConditions), nil
	}
	_ = err

	recommendation := ps.analyzeMLPrediction(response, networkConditions)

	ps.recommendations[networkConditions.NetworkType] = recommendation
	ps.lastAnalysis = time.Now()

	ps.history = append(ps.history, *recommendation)
	if len(ps.history) > ps.maxHistory {
		ps.history = ps.history[1:]
	}

	return recommendation, nil
}

func (ps *ProtocolSelector) createTestPacket(conditions *NetworkConditions) []byte {
	testPacket := make([]byte, 128)

	testPacket[0] = byte(conditions.ThreatLevel)
	testPacket[1] = byte(conditions.NetworkType[0])

	latencyBytes := make([]byte, 8)
	latencyBytes[0] = byte(conditions.Latency.Milliseconds() / 10)
	copy(testPacket[2:10], latencyBytes)

	return testPacket
}

func (ps *ProtocolSelector) analyzeMLPrediction(response *types.MLPredictionResponse, conditions *NetworkConditions) *ProtocolRecommendation {
	if response == nil || len(response.Predictions) == 0 {
		return ps.getDefaultRecommendation(conditions)
	}

	pred := response.Predictions[0]
	recommendation := &ProtocolRecommendation{
		Confidence:            pred.Confidence,
		ExpectedEffectiveness: 1.0 - float64(pred.DPIType)*0.1,
		ThreatLevel:           conditions.ThreatLevel,
	}

	switch {
	case pred.DPIType >= 5:
		recommendation.Protocol = "grpc"
		recommendation.Reason = "Advanced heuristics detected, using gRPC for API mimicry"
		recommendation.ExpectedEffectiveness = 0.95

	case pred.DPIType >= 4:
		if conditions.Bandwidth > 50 {
			recommendation.Protocol = "http2"
			recommendation.Reason = "ML-based DPI detected, using HTTP/2 multiplexing"
			recommendation.ExpectedEffectiveness = 0.90
		} else {
			recommendation.Protocol = "tls"
			recommendation.Reason = "ML-based DPI detected, using TLS for maximum evasion"
			recommendation.ExpectedEffectiveness = 0.85
		}

	case pred.DPIType >= 3:
		recommendation.Protocol = "dtls"
		recommendation.Reason = "Statistical DPI detected, using DTLS for UDP traffic"
		recommendation.ExpectedEffectiveness = 0.75

	case pred.DPIType >= 2:
		recommendation.Protocol = "tls"
		recommendation.Reason = "Flow analysis detected, using TLS with obfuscation"
		recommendation.ExpectedEffectiveness = 0.70

	case pred.DPIType >= 1:
		if conditions.ThreatLevel >= 7 {
			recommendation.Protocol = "tls"
			recommendation.Reason = "High threat level with DPI, using TLS"
			recommendation.ExpectedEffectiveness = 0.80
		} else {
			recommendation.Protocol = "noise_ik"
			recommendation.Reason = "Low-moderate threat with DPI, using Noise IK"
			recommendation.ExpectedEffectiveness = 0.65
		}

	default:
		recommendation.Protocol = "noise_ik"
		recommendation.Reason = "No DPI detected, using Noise IK for performance"
		recommendation.ExpectedEffectiveness = 0.90
	}

	if conditions.NetworkType == "corporate" || conditions.NetworkType == "government" {
		if recommendation.Protocol == "noise_ik" {
			recommendation.Protocol = "tls"
			recommendation.Reason += " (switched to TLS for corporate network)"
			recommendation.ExpectedEffectiveness += 0.1
		}
	}

	if conditions.Latency > 200*time.Millisecond {
		if recommendation.Protocol == "tls" {
			recommendation.Protocol = "dtls"
			recommendation.Reason += " (switched to DTLS for high latency)"
		}
	}

	return recommendation
}

func (ps *ProtocolSelector) getDefaultRecommendation(conditions *NetworkConditions) *ProtocolRecommendation {
	recommendation := &ProtocolRecommendation{
		ThreatLevel:           conditions.ThreatLevel,
		Confidence:            0.5,
		Reason:                "Default recommendation (ML unavailable)",
		ExpectedEffectiveness: 0.6,
	}

	switch {
	case conditions.ThreatLevel >= 8:
		recommendation.Protocol = "tls"
		recommendation.ExpectedEffectiveness = 0.85
	case conditions.ThreatLevel >= 6:
		recommendation.Protocol = "dtls"
		recommendation.ExpectedEffectiveness = 0.75
	case conditions.ThreatLevel >= 4:
		recommendation.Protocol = "noise_ik"
		recommendation.ExpectedEffectiveness = 0.65
	default:
		recommendation.Protocol = "noise_ik"
		recommendation.ExpectedEffectiveness = 0.90
	}

	return recommendation
}

type NetworkConditions struct {
	ThreatLevel int
	NetworkType string
	Latency     time.Duration
	Bandwidth   int
	PacketLoss  float64
	Jitter      time.Duration
}

func (ps *ProtocolSelector) ShouldUseTLS(conditions *NetworkConditions) (bool, float64, error) {
	recommendation, err := ps.SelectProtocol(conditions)
	if err != nil {
		return false, 0.0, err
	}

	useTLS := recommendation.Protocol == "tls" || recommendation.Protocol == "dtls"
	return useTLS, recommendation.Confidence, nil
}

func (ps *ProtocolSelector) GetRecommendationHistory() []ProtocolRecommendation {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	history := make([]ProtocolRecommendation, len(ps.history))
	copy(history, ps.history)
	return history
}

func (ps *ProtocolSelector) GetLastRecommendation(networkType string) *ProtocolRecommendation {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	return ps.recommendations[networkType]
}
