package ml


import (
	"math"
	"sort"
	"sync"
)

const (
	adversarialConfTarget = 0.45
	adversarialBudgetDefault = 12
	adversarialMinLen = 32
	adversarialSafeZoneFrac = 0.35
)

type AdversarialEngine struct {
	engine  *NativeMLEngine
	mu      sync.Mutex
	enabled int32
	Enabled bool
}

func NewAdversarialEngine(engine *NativeMLEngine) *AdversarialEngine {
	return &AdversarialEngine{engine: engine, Enabled: true}
}

func (ae *AdversarialEngine) PerturbPacket(data []byte, budget int) []byte {
	if !ae.Enabled || ae.engine == nil || len(data) < adversarialMinLen {
		return data
	}
	if budget <= 0 {
		budget = adversarialBudgetDefault
	}

	conf := ae.dpiConf(data)
	if conf < adversarialConfTarget {
		return data
	}

	safeStart := int(float64(len(data)) * (1.0 - adversarialSafeZoneFrac))
	if safeStart < adversarialMinLen {
		safeStart = adversarialMinLen
	}
	if safeStart >= len(data) {
		return data
	}

	sensitivity := ae.estimateSensitivity(data, safeStart)

	result := ae.greedyFlip(data, safeStart, sensitivity, budget, conf)
	return result
}

func (ae *AdversarialEngine) dpiConf(data []byte) float64 {
	resp := ae.engine.Predict(data, "tcp", "outbound")
	if resp == nil || len(resp.Predictions) == 0 {
		return 0
	}
	p := resp.Predictions[0]
	if p.DPIType <= 0 {
		return 0
	}
	return p.Confidence
}

type byteCandidate struct {
	pos  int
	gain float64
}

func (ae *AdversarialEngine) estimateSensitivity(data []byte, safeStart int) []byteCandidate {
	baseConf := ae.dpiConf(data)
	n := len(data) - safeStart
	candidates := make([]byteCandidate, 0, n)

	step := 1
	if n > 60 {
		step = 3
	}

	probe := make([]byte, len(data))
	copy(probe, data)

	for i := 0; i < n; i += step {
		pos := safeStart + i
		orig := probe[pos]
		probe[pos] = orig ^ 0xFF
		newConf := ae.dpiConf(probe)
		gain := baseConf - newConf
		if gain > 0 {
			candidates = append(candidates, byteCandidate{pos: pos, gain: gain})
		}
		probe[pos] = orig
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].gain > candidates[j].gain
	})
	return candidates
}

func (ae *AdversarialEngine) greedyFlip(
	data []byte,
	safeStart int,
	candidates []byteCandidate,
	budget int,
	initialConf float64,
) []byte {
	if len(candidates) == 0 {
		return data
	}

	result := make([]byte, len(data))
	copy(result, data)
	currentConf := initialConf
	changed := 0

	for _, c := range candidates {
		if changed >= budget {
			break
		}
		if currentConf < adversarialConfTarget {
			break
		}
		orig := result[c.pos]
		result[c.pos] = orig ^ 0xFF
		newConf := ae.dpiConf(result)
		if newConf < currentConf {
			currentConf = newConf
			changed++
		} else {
			result[c.pos] = orig
		}
	}

	return result
}

func entropyOfSlice(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	e := 0.0
	for _, c := range freq {
		if c > 0 {
			p := float64(c) / n
			e -= p * math.Log2(p)
		}
	}
	return e
}

func (ae *AdversarialEngine) PerturbEntropy(data []byte, targetEntropy float64) []byte {
	if len(data) < adversarialMinLen {
		return data
	}
	safeStart := int(float64(len(data)) * (1.0 - adversarialSafeZoneFrac))
	if safeStart >= len(data) {
		return data
	}
	current := entropyOfSlice(data[safeStart:])
	if current <= targetEntropy {
		return data
	}
	result := make([]byte, len(data))
	copy(result, data)
	printable := []byte("                abcdefghijklmnopqrstuvwxyz0123456789")
	for i := safeStart; i < len(result); i++ {
		result[i] = printable[int(result[i])%len(printable)]
		if entropyOfSlice(result[safeStart:]) <= targetEntropy {
			break
		}
	}
	return result
}

var (
	globalAdversarialOnce   sync.Once
	globalAdversarialEngine *AdversarialEngine
)

func GetAdversarialEngine() *AdversarialEngine {
	globalAdversarialOnce.Do(func() {
		globalAdversarialEngine = NewAdversarialEngine(nativeEngine)
	})
	return globalAdversarialEngine
}
