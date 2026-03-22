package ml

import (
	"encoding/json"
	"math"
	mrand "math/rand"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"whispera/internal/obfuscation/ml/gnet"
)


const (
	RLStateSize    = 16
	RLActionSize   = 28
	RLHidden1      = 64
	RLHidden2      = 32
	RLBufferSize   = 2000
	RLBatchSize    = 16
	RLGamma        = 0.95
	RLEpsilonStart = 0.3
	RLEpsilonMin   = 0.05
	RLEpsilonDecay = 0.995
	RLTargetSync   = 50
	RLTrainEvery   = 10
)

type Experience struct {
	State     []float64
	Action    int
	Reward    float64
	NextState []float64
	Done      bool
}

type RLTransportAgent struct {
	mu sync.RWMutex

	qNet    *gnet.GorgoniaNet
	target  *gnet.GorgoniaNet
	buffer  []Experience
	bufIdx  int
	bufFull bool

	epsilon    float64
	stepCount  int64
	trainCount int64

	transportNames []string
	transportIndex map[string]int

	modelDir string
}

func NewRLTransportAgent(modelDir string) *RLTransportAgent {
	agent := &RLTransportAgent{
		qNet:       gnet.New([]int{RLStateSize, RLHidden1, RLHidden2, RLActionSize}),
		buffer:     make([]Experience, RLBufferSize),
		epsilon:    RLEpsilonStart,
		modelDir:   modelDir,
		transportNames: []string{
			"tcp", "udp", "h2c", "shadowtls", "ws", "wss",
			"grpc", "quic", "kcp", "obfs4", "meek",
			"utls", "reality", "vless", "vmess", "trojan",
			"hysteria", "hysteria2", "tuic", "ssh", "wireguard",
			"cdn-ws", "cdn-grpc", "fragment", "tlsfrag",
			"vkvideo", "okhttp", "doh",
		},
		transportIndex: make(map[string]int),
	}
	for i, name := range agent.transportNames {
		agent.transportIndex[name] = i
	}
	agent.target = gnet.Clone(agent.qNet)
	if !agent.loadPolicy() {
		agent.PreSeed()
	}
	return agent
}

func (a *RLTransportAgent) EncodeState(
	rttMs [4]float64,
	recentSuccessRate float64,
	recentFailRate float64,
	dpiDetected bool,
	anomalyScore float64,
	hourOfDay int,
	blockRisk float64,
) []float64 {
	s := make([]float64, RLStateSize)
	for i := 0; i < 4 && i < len(rttMs); i++ {
		s[i] = math.Min(rttMs[i]/500.0, 1.0)
	}
	s[4] = recentSuccessRate
	s[5] = recentFailRate
	if dpiDetected {
		s[6] = 1.0
	}
	s[7] = math.Min(anomalyScore, 1.0)
	s[8] = math.Sin(2 * math.Pi * float64(hourOfDay) / 24.0)
	s[9] = math.Cos(2 * math.Pi * float64(hourOfDay) / 24.0)
	s[10] = blockRisk
	return s
}

func (a *RLTransportAgent) SelectTransport(state []float64) (transport string, actionIdx int, explored bool) {
	a.mu.RLock()
	eps := a.epsilon
	a.mu.RUnlock()

	if mrand.Float64() < eps {
		idx := mrand.Intn(len(a.transportNames))
		return a.transportNames[idx], idx, true
	}

	a.mu.RLock()
	qvals := a.qNet.Forward(state)
	a.mu.RUnlock()

	best := 0
	for i := 1; i < len(qvals); i++ {
		if qvals[i] > qvals[best] {
			best = i
		}
	}
	if best < len(a.transportNames) {
		return a.transportNames[best], best, false
	}
	return a.transportNames[0], 0, false
}

func ComputeReward(success bool, latencyMs float64) float64 {
	if !success {
		return -1.0
	}
	latencyBonus := math.Max(0, 1.0-latencyMs/2000.0)
	return 0.5 + 0.5*latencyBonus
}

func (a *RLTransportAgent) RecordExperience(state []float64, action int, reward float64, nextState []float64, done bool) {
	a.mu.Lock()
	a.buffer[a.bufIdx] = Experience{
		State:     state,
		Action:    action,
		Reward:    reward,
		NextState: nextState,
		Done:      done,
	}
	a.bufIdx = (a.bufIdx + 1) % RLBufferSize
	if a.bufIdx == 0 {
		a.bufFull = true
	}
	step := atomic.AddInt64(&a.stepCount, 1)
	a.mu.Unlock()

	a.mu.Lock()
	a.epsilon = math.Max(RLEpsilonMin, a.epsilon*RLEpsilonDecay)
	a.mu.Unlock()

	if step%RLTrainEvery == 0 {
		go a.trainStep()
	}

	if step%RLTargetSync == 0 {
		a.mu.Lock()
		a.target = gnet.Clone(a.qNet)
		a.mu.Unlock()
	}
}

func (a *RLTransportAgent) trainStep() {
	a.mu.RLock()
	size := a.bufIdx
	if a.bufFull {
		size = RLBufferSize
	}
	if size < RLBatchSize*2 {
		a.mu.RUnlock()
		return
	}
	a.mu.RUnlock()

	batch := make([]Experience, RLBatchSize)
	a.mu.RLock()
	for i := 0; i < RLBatchSize; i++ {
		idx := mrand.Intn(size)
		batch[i] = a.buffer[idx]
	}
	a.mu.RUnlock()

	a.mu.Lock()
	defer a.mu.Unlock()

	lr := 0.001

	for _, exp := range batch {
		layerOutputs := a.fullForward(exp.State)
		qvals := layerOutputs[len(layerOutputs)-1]

		var targetQ float64
		if exp.Done {
			targetQ = exp.Reward
		} else {
			nextQ := a.target.Forward(exp.NextState)
			maxNextQ := nextQ[0]
			for _, q := range nextQ[1:] {
				if q > maxNextQ {
					maxNextQ = q
				}
			}
			targetQ = exp.Reward + RLGamma*maxNextQ
		}

		dOutput := make([]float64, len(qvals))
		dOutput[exp.Action] = -(targetQ - qvals[exp.Action])

		a.fullBackprop(layerOutputs, dOutput, lr)
	}

	atomic.AddInt64(&a.trainCount, 1)

	if a.trainCount%100 == 0 {
		a.savePolicyLocked()
	}
}

func (a *RLTransportAgent) fullForward(input []float64) [][]float64 {
	activations := make([][]float64, len(a.qNet.Layers)+1)
	activations[0] = input
	current := input
	for i, ld := range a.qNet.Layers {
		out := make([]float64, ld.OutSize)
		for j := 0; j < ld.OutSize; j++ {
			sum := ld.B[j]
			for k := 0; k < ld.InSize && k < len(current); k++ {
				sum += current[k] * ld.W[k*ld.OutSize+j]
			}
			if i < len(a.qNet.Layers)-1 {
				if sum < 0 {
					sum = 0
				}
			}
			out[j] = sum
		}
		activations[i+1] = out
		current = out
	}
	return activations
}

func (a *RLTransportAgent) fullBackprop(activations [][]float64, dOutput []float64, lr float64) {
	delta := dOutput

	for i := len(a.qNet.Layers) - 1; i >= 0; i-- {
		ld := &a.qNet.Layers[i]
		input := activations[i]
		output := activations[i+1]

		if i < len(a.qNet.Layers)-1 {
			for j := range delta {
				if output[j] <= 0 {
					delta[j] = 0
				}
			}
		}

		var prevDelta []float64
		if i > 0 {
			prevDelta = make([]float64, ld.InSize)
			for k := 0; k < ld.InSize; k++ {
				for j := 0; j < ld.OutSize; j++ {
					prevDelta[k] += ld.W[k*ld.OutSize+j] * delta[j]
				}
			}
		}

		for k := 0; k < ld.InSize && k < len(input); k++ {
			for j := 0; j < ld.OutSize; j++ {
				ld.W[k*ld.OutSize+j] -= lr * delta[j] * input[k]
			}
		}
		for j := 0; j < ld.OutSize; j++ {
			ld.B[j] -= lr * delta[j]
		}

		delta = prevDelta
	}
}

func (a *RLTransportAgent) PreSeed() {
	a.mu.Lock()
	defer a.mu.Unlock()

	priors := map[string]float64{
		"tcp": 0.3, "udp": 0.2, "h2c": 0.5, "shadowtls": 0.7, "ws": 0.6, "wss": 0.65,
		"grpc": 0.6, "quic": 0.4, "kcp": 0.3, "obfs4": 0.7, "meek": 0.5,
		"utls": 0.6, "reality": 0.8, "vless": 0.7, "vmess": 0.65, "trojan": 0.7,
		"hysteria": 0.6, "hysteria2": 0.65, "tuic": 0.55, "ssh": 0.5, "wireguard": 0.4,
		"cdn-ws": 0.75, "cdn-grpc": 0.75, "fragment": 0.6, "tlsfrag": 0.6,
		"vkvideo": 0.8, "okhttp": 0.5, "doh": 0.6,
	}

	conditions := [][4]float64{
		{50, 30, 40, 60},
		{200, 150, 300, 400},
		{9999, 100, 80, 90},
		{9999, 9999, 9999, 9999},
	}

	for _, rtt := range conditions {
		dpiDetected := rtt[0] > 5000 && rtt[1] < 1000
		blockRisk := 0.0
		if dpiDetected {
			blockRisk = 0.7
		}

		state := make([]float64, RLStateSize)
		for i := 0; i < 4; i++ {
			state[i] = math.Min(rtt[i]/500.0, 1.0)
		}
		state[4] = 0.5
		state[5] = 0.5
		if dpiDetected {
			state[6] = 1.0
		}
		state[10] = blockRisk

		for name, baseReward := range priors {
			idx, ok := a.transportIndex[name]
			if !ok {
				continue
			}
			reward := baseReward
			if dpiDetected {
				switch name {
				case "reality", "shadowtls", "vkvideo", "cdn-ws", "cdn-grpc", "trojan":
					reward = math.Min(reward+0.2, 1.0)
				case "tcp", "udp", "quic":
					reward = math.Max(reward-0.4, -1.0)
				}
			}
			if rtt[0] > 5000 && rtt[1] > 5000 {
				reward = -0.8
			}

			reward += (mrand.Float64() - 0.5) * 0.1

			nextState := make([]float64, RLStateSize)
			copy(nextState, state)

			a.buffer[a.bufIdx] = Experience{
				State:     state,
				Action:    idx,
				Reward:    reward,
				NextState: nextState,
				Done:      reward < 0,
			}
			a.bufIdx = (a.bufIdx + 1) % RLBufferSize
			if a.bufIdx == 0 {
				a.bufFull = true
			}
			atomic.AddInt64(&a.stepCount, 1)
		}
	}

	for i := 0; i < 20; i++ {
		size := a.bufIdx
		if a.bufFull {
			size = RLBufferSize
		}
		if size < RLBatchSize*2 {
			break
		}
		batch := make([]Experience, RLBatchSize)
		for j := 0; j < RLBatchSize; j++ {
			batch[j] = a.buffer[mrand.Intn(size)]
		}
		for _, exp := range batch {
			layerOutputs := a.fullForward(exp.State)
			qvals := layerOutputs[len(layerOutputs)-1]

			var targetQ float64
			if exp.Done {
				targetQ = exp.Reward
			} else {
				nextQ := a.target.Forward(exp.NextState)
				maxNextQ := nextQ[0]
				for _, q := range nextQ[1:] {
					if q > maxNextQ {
						maxNextQ = q
					}
				}
				targetQ = exp.Reward + RLGamma*maxNextQ
			}
			dOut := make([]float64, len(qvals))
			dOut[exp.Action] = -(targetQ - qvals[exp.Action])
			a.fullBackprop(layerOutputs, dOut, 0.001)
		}
	}

	a.target = gnet.Clone(a.qNet)
}

func (a *RLTransportAgent) TransportIndex(name string) int {
	if idx, ok := a.transportIndex[name]; ok {
		return idx
	}
	return -1
}

func (a *RLTransportAgent) Stats() map[string]interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()
	size := a.bufIdx
	if a.bufFull {
		size = RLBufferSize
	}
	return map[string]interface{}{
		"epsilon":     a.epsilon,
		"step_count":  atomic.LoadInt64(&a.stepCount),
		"train_count": atomic.LoadInt64(&a.trainCount),
		"buffer_size": size,
	}
}

type rlPolicyState struct {
	Layers  []gnet.LayerDef `json:"layers"`
	Epsilon float64         `json:"epsilon"`
	Steps   int64           `json:"steps"`
}

func (a *RLTransportAgent) savePolicyLocked() {
	if a.modelDir == "" {
		return
	}
	state := rlPolicyState{
		Layers:  a.qNet.Layers,
		Epsilon: a.epsilon,
		Steps:   atomic.LoadInt64(&a.stepCount),
	}
	data, err := json.Marshal(state)
	if err != nil {
		return
	}
	os.MkdirAll(a.modelDir, 0700)
	os.WriteFile(filepath.Join(a.modelDir, "rl_policy.json"), data, 0600)
}

func (a *RLTransportAgent) loadPolicy() bool {
	if a.modelDir == "" {
		return false
	}
	data, err := os.ReadFile(filepath.Join(a.modelDir, "rl_policy.json"))
	if err != nil {
		return false
	}
	var state rlPolicyState
	if err := json.Unmarshal(data, &state); err != nil {
		return false
	}
	if len(state.Layers) > 0 {
		loaded := &gnet.GorgoniaNet{Layers: state.Layers}
		a.mu.Lock()
		a.qNet = loaded
		a.target = gnet.Clone(loaded)
		a.epsilon = state.Epsilon
		atomic.StoreInt64(&a.stepCount, state.Steps)
		a.mu.Unlock()
		return true
	}
	return false
}
