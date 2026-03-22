package ml

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"sync"
	"time"
)

const (
	FlowInputSize  = 8  // per-packet flow features
	FlowHiddenSize = 32 // LSTM hidden/cell state
	FlowOutputSize = 7  // same as TrafficClasses
	FlowMaxAge     = 5 * time.Minute
	FlowMaxEntries = 10000
	FlowBPTTDepth  = 8     // truncated BPTT window
	FlowLearnRate  = 0.001 // online learning rate
)

// FlowState holds the LSTM cell and hidden state for a single flow,
// plus a history window for truncated BPTT.
type FlowState struct {
	Hidden    []float64 // h_t
	Cell      []float64 // c_t (LSTM cell state)
	PacketNum int
	LastSeen  time.Time
	// History for truncated BPTT (circular buffer of last FlowBPTTDepth steps).
	History   []flowStep
	HistIdx   int
	HistFull  bool
	ClassVotes [FlowOutputSize]int
}

// flowStep stores one timestep's data for BPTT.
type flowStep struct {
	Input    []float64 // x_t
	HidPrev  []float64 // h_{t-1}
	CellPrev []float64 // c_{t-1}
	// Gate pre-activations (for gradient computation).
	ForgetGate []float64 // f_t (after sigmoid)
	InputGate  []float64 // i_t (after sigmoid)
	OutputGate []float64 // o_t (after sigmoid)
	CandCell   []float64 // c_tilde (after tanh)
	CellNew    []float64 // c_t
	HidNew     []float64 // h_t
}

// FlowAnalyzer maintains per-flow LSTM state with online learning.
type FlowAnalyzer struct {
	mu    sync.RWMutex
	flows map[string]*FlowState

	// LSTM weights: 4 gates (forget, input, output, candidate cell).
	// Each gate: W_x [InputSize × HiddenSize] + W_h [HiddenSize × HiddenSize] + b [HiddenSize]
	WxF, WhF, BF []float64 // forget gate
	WxI, WhI, BI []float64 // input gate
	WxO, WhO, BO []float64 // output gate
	WxC, WhC, BC []float64 // candidate cell (g / c_tilde)

	// Output layer: hidden → class logits.
	Wo []float64 // HiddenSize × FlowOutputSize
	Bo []float64 // FlowOutputSize
}

// NewFlowAnalyzer creates a new LSTM-based flow analyzer with Xavier-initialized weights.
func NewFlowAnalyzer() *FlowAnalyzer {
	fa := &FlowAnalyzer{
		flows: make(map[string]*FlowState),
		// Forget gate.
		WxF: xavierInit(FlowInputSize, FlowHiddenSize),
		WhF: xavierInit(FlowHiddenSize, FlowHiddenSize),
		BF:  biasInit(FlowHiddenSize, 1.0), // bias=1 so forget gate starts open
		// Input gate.
		WxI: xavierInit(FlowInputSize, FlowHiddenSize),
		WhI: xavierInit(FlowHiddenSize, FlowHiddenSize),
		BI:  make([]float64, FlowHiddenSize),
		// Output gate.
		WxO: xavierInit(FlowInputSize, FlowHiddenSize),
		WhO: xavierInit(FlowHiddenSize, FlowHiddenSize),
		BO:  make([]float64, FlowHiddenSize),
		// Candidate cell.
		WxC: xavierInit(FlowInputSize, FlowHiddenSize),
		WhC: xavierInit(FlowHiddenSize, FlowHiddenSize),
		BC:  make([]float64, FlowHiddenSize),
		// Output layer.
		Wo: xavierInit(FlowHiddenSize, FlowOutputSize),
		Bo: make([]float64, FlowOutputSize),
	}
	go fa.cleanupLoop()
	return fa
}

// biasInit creates a bias vector filled with a constant value.
func biasInit(size int, val float64) []float64 {
	b := make([]float64, size)
	for i := range b {
		b[i] = val
	}
	return b
}

// ExtractFlowFeatures extracts per-packet features for the flow model.
func ExtractFlowFeatures(data []byte, direction string, interArrivalMs float64) []float64 {
	f := make([]float64, FlowInputSize)
	n := float64(len(data))

	f[0] = math.Min(n/1500.0, 1.0)              // normalized size
	f[1] = math.Log2(n+1) / 11.0                 // log size normalized
	if direction == "outbound" {
		f[2] = 1.0
	}
	f[3] = math.Min(interArrivalMs/1000.0, 1.0)  // inter-arrival time
	f[4] = math.Min(interArrivalMs/100.0, 1.0)   // fine-grained IAT

	if len(data) > 0 {
		f[5] = float64(data[0]) / 255.0
	}
	switch {
	case n < 100:
		f[6] = 0.0
	case n < 500:
		f[6] = 0.5
	default:
		f[6] = 1.0
	}
	if n > 0 {
		var freq [256]int
		for _, b := range data {
			freq[b]++
		}
		ent := 0.0
		for _, c := range freq {
			if c > 0 {
				p := float64(c) / n
				ent -= p * math.Log2(p)
			}
		}
		f[7] = ent / 8.0
	}
	return f
}

// Update processes a new packet through the LSTM and returns class logits.
func (fa *FlowAnalyzer) Update(flowKey string, packetFeatures []float64) []float64 {
	fa.mu.Lock()
	state, exists := fa.flows[flowKey]
	if !exists {
		state = &FlowState{
			Hidden:  make([]float64, FlowHiddenSize),
			Cell:    make([]float64, FlowHiddenSize),
			History: make([]flowStep, FlowBPTTDepth),
		}
		fa.flows[flowKey] = state
	}
	state.PacketNum++
	state.LastSeen = time.Now()

	hPrev := make([]float64, FlowHiddenSize)
	cPrev := make([]float64, FlowHiddenSize)
	copy(hPrev, state.Hidden)
	copy(cPrev, state.Cell)
	fa.mu.Unlock()

	// LSTM forward pass.
	step := fa.lstmForward(packetFeatures, hPrev, cPrev)

	// Output layer: logits = Wo^T * h_new + Bo
	output := make([]float64, FlowOutputSize)
	for j := 0; j < FlowOutputSize; j++ {
		sum := fa.Bo[j]
		for i := 0; i < FlowHiddenSize; i++ {
			sum += fa.Wo[i*FlowOutputSize+j] * step.HidNew[i]
		}
		output[j] = sum
	}

	// Save state and history step.
	fa.mu.Lock()
	copy(state.Hidden, step.HidNew)
	copy(state.Cell, step.CellNew)
	state.History[state.HistIdx] = step
	state.HistIdx = (state.HistIdx + 1) % FlowBPTTDepth
	if state.HistIdx == 0 {
		state.HistFull = true
	}
	fa.mu.Unlock()

	return output
}

// lstmForward computes one LSTM timestep.
func (fa *FlowAnalyzer) lstmForward(x, hPrev, cPrev []float64) flowStep {
	H := FlowHiddenSize
	step := flowStep{
		Input:      copyF64(x),
		HidPrev:    copyF64(hPrev),
		CellPrev:   copyF64(cPrev),
		ForgetGate: make([]float64, H),
		InputGate:  make([]float64, H),
		OutputGate: make([]float64, H),
		CandCell:   make([]float64, H),
		CellNew:    make([]float64, H),
		HidNew:     make([]float64, H),
	}

	for j := 0; j < H; j++ {
		var fSum, iSum, oSum, cSum float64
		fSum = fa.BF[j]
		iSum = fa.BI[j]
		oSum = fa.BO[j]
		cSum = fa.BC[j]
		for k := 0; k < len(x) && k < FlowInputSize; k++ {
			fSum += fa.WxF[k*H+j] * x[k]
			iSum += fa.WxI[k*H+j] * x[k]
			oSum += fa.WxO[k*H+j] * x[k]
			cSum += fa.WxC[k*H+j] * x[k]
		}
		for k := 0; k < H; k++ {
			fSum += fa.WhF[k*H+j] * hPrev[k]
			iSum += fa.WhI[k*H+j] * hPrev[k]
			oSum += fa.WhO[k*H+j] * hPrev[k]
			cSum += fa.WhC[k*H+j] * hPrev[k]
		}
		step.ForgetGate[j] = sigmoid(fSum)
		step.InputGate[j] = sigmoid(iSum)
		step.OutputGate[j] = sigmoid(oSum)
		step.CandCell[j] = math.Tanh(cSum)

		// c_t = f_t * c_{t-1} + i_t * c_tilde
		step.CellNew[j] = step.ForgetGate[j]*cPrev[j] + step.InputGate[j]*step.CandCell[j]
		// h_t = o_t * tanh(c_t)
		step.HidNew[j] = step.OutputGate[j] * math.Tanh(step.CellNew[j])
	}
	return step
}

// LearnOnline performs truncated BPTT on a flow given the true class label.
// Called when we have a ground-truth label (from pattern matching or high-confidence prediction).
func (fa *FlowAnalyzer) LearnOnline(flowKey string, trueClass int) {
	if trueClass < 0 || trueClass >= FlowOutputSize {
		return
	}

	fa.mu.RLock()
	state, exists := fa.flows[flowKey]
	if !exists {
		fa.mu.RUnlock()
		return
	}
	histLen := state.HistIdx
	if state.HistFull {
		histLen = FlowBPTTDepth
	}
	if histLen == 0 {
		fa.mu.RUnlock()
		return
	}

	// Collect history steps in chronological order.
	steps := make([]flowStep, histLen)
	if state.HistFull {
		for i := 0; i < FlowBPTTDepth; i++ {
			idx := (state.HistIdx + i) % FlowBPTTDepth
			steps[i] = state.History[idx]
		}
	} else {
		copy(steps, state.History[:histLen])
	}
	fa.mu.RUnlock()

	H := FlowHiddenSize
	lr := FlowLearnRate

	// Forward pass on the last step to get output.
	lastH := steps[histLen-1].HidNew
	output := make([]float64, FlowOutputSize)
	for j := 0; j < FlowOutputSize; j++ {
		sum := fa.Bo[j]
		for i := 0; i < H; i++ {
			sum += fa.Wo[i*FlowOutputSize+j] * lastH[i]
		}
		output[j] = sum
	}

	// Softmax + cross-entropy gradient: dL/d_logit = prob - one_hot.
	probs := softmaxF64(output)
	dOutput := make([]float64, FlowOutputSize)
	for j := 0; j < FlowOutputSize; j++ {
		dOutput[j] = probs[j]
	}
	dOutput[trueClass] -= 1.0

	// Gradient for output layer weights.
	fa.mu.Lock()
	defer fa.mu.Unlock()

	for i := 0; i < H; i++ {
		for j := 0; j < FlowOutputSize; j++ {
			fa.Wo[i*FlowOutputSize+j] -= lr * dOutput[j] * lastH[i]
		}
	}
	for j := 0; j < FlowOutputSize; j++ {
		fa.Bo[j] -= lr * dOutput[j]
	}

	// dL/dh for the last timestep (from output layer).
	dh := make([]float64, H)
	for i := 0; i < H; i++ {
		for j := 0; j < FlowOutputSize; j++ {
			dh[i] += fa.Wo[i*FlowOutputSize+j] * dOutput[j]
		}
	}
	dc := make([]float64, H) // dL/dc — accumulated through BPTT

	// Truncated BPTT backwards through history.
	for t := histLen - 1; t >= 0; t-- {
		s := &steps[t]

		// dL/dc_t from dL/dh_t:
		// h_t = o_t * tanh(c_t), so dc += dh * o_t * (1 - tanh(c_t)^2)
		tanhC := make([]float64, H)
		for j := 0; j < H; j++ {
			tanhC[j] = math.Tanh(s.CellNew[j])
			dc[j] += dh[j] * s.OutputGate[j] * (1 - tanhC[j]*tanhC[j])
		}

		// Gate gradients.
		dForget := make([]float64, H) // dL/d(f pre-activation)
		dInput := make([]float64, H)
		dOutGate := make([]float64, H)
		dCand := make([]float64, H)

		for j := 0; j < H; j++ {
			// Output gate: dL/do_pre = dh * tanh(c) * o*(1-o)
			dOutGate[j] = dh[j] * tanhC[j] * s.OutputGate[j] * (1 - s.OutputGate[j])
			// Forget gate: dL/df_pre = dc * c_{t-1} * f*(1-f)
			dForget[j] = dc[j] * s.CellPrev[j] * s.ForgetGate[j] * (1 - s.ForgetGate[j])
			// Input gate: dL/di_pre = dc * c_tilde * i*(1-i)
			dInput[j] = dc[j] * s.CandCell[j] * s.InputGate[j] * (1 - s.InputGate[j])
			// Candidate cell: dL/dc_tilde_pre = dc * i * (1 - c_tilde^2)
			dCand[j] = dc[j] * s.InputGate[j] * (1 - s.CandCell[j]*s.CandCell[j])
		}

		// Update weights (all 4 gates).
		fa.updateGateWeights(fa.WxF, fa.WhF, fa.BF, dForget, s.Input, s.HidPrev, lr)
		fa.updateGateWeights(fa.WxI, fa.WhI, fa.BI, dInput, s.Input, s.HidPrev, lr)
		fa.updateGateWeights(fa.WxO, fa.WhO, fa.BO, dOutGate, s.Input, s.HidPrev, lr)
		fa.updateGateWeights(fa.WxC, fa.WhC, fa.BC, dCand, s.Input, s.HidPrev, lr)

		// Propagate gradients to previous timestep.
		// dh_{t-1} = Wh^T * d_gate for all 4 gates
		newDh := make([]float64, H)
		for k := 0; k < H; k++ {
			for j := 0; j < H; j++ {
				newDh[k] += fa.WhF[k*H+j] * dForget[j]
				newDh[k] += fa.WhI[k*H+j] * dInput[j]
				newDh[k] += fa.WhO[k*H+j] * dOutGate[j]
				newDh[k] += fa.WhC[k*H+j] * dCand[j]
			}
		}
		dh = newDh

		// dc_{t-1} = dc * f_t
		newDc := make([]float64, H)
		for j := 0; j < H; j++ {
			newDc[j] = dc[j] * s.ForgetGate[j]
		}
		dc = newDc
	}
}

// updateGateWeights applies gradient descent to a single gate's weights.
func (fa *FlowAnalyzer) updateGateWeights(Wx, Wh, B, dGate, x, hPrev []float64, lr float64) {
	H := FlowHiddenSize
	for j := 0; j < H; j++ {
		// Wx update.
		for k := 0; k < FlowInputSize && k < len(x); k++ {
			Wx[k*H+j] -= lr * dGate[j] * x[k]
		}
		// Wh update.
		for k := 0; k < H; k++ {
			Wh[k*H+j] -= lr * dGate[j] * hPrev[k]
		}
		// Bias update.
		B[j] -= lr * dGate[j]
	}
}

// GetFlowConfidence returns the accumulated flow-level classification.
func (fa *FlowAnalyzer) GetFlowConfidence(flowKey string) (classID int, confidence float64) {
	fa.mu.RLock()
	state, exists := fa.flows[flowKey]
	fa.mu.RUnlock()
	if !exists || state.PacketNum < 3 {
		return -1, 0
	}

	fa.mu.RLock()
	hidden := make([]float64, FlowHiddenSize)
	copy(hidden, state.Hidden)
	fa.mu.RUnlock()

	output := make([]float64, FlowOutputSize)
	for j := 0; j < FlowOutputSize; j++ {
		sum := fa.Bo[j]
		for i := 0; i < FlowHiddenSize; i++ {
			sum += fa.Wo[i*FlowOutputSize+j] * hidden[i]
		}
		output[j] = sum
	}

	probs := softmaxF64(output)
	best := 0
	for i := 1; i < len(probs); i++ {
		if probs[i] > probs[best] {
			best = i
		}
	}
	return best, probs[best]
}

func sigmoid(x float64) float64 {
	return 1.0 / (1.0 + math.Exp(-x))
}

func copyF64(s []float64) []float64 {
	out := make([]float64, len(s))
	copy(out, s)
	return out
}

func (fa *FlowAnalyzer) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		fa.mu.Lock()
		cutoff := time.Now().Add(-FlowMaxAge)
		for k, v := range fa.flows {
			if v.LastSeen.Before(cutoff) {
				delete(fa.flows, k)
			}
		}
		for len(fa.flows) > FlowMaxEntries {
			var oldestKey string
			var oldestTime time.Time
			first := true
			for k, v := range fa.flows {
				if first || v.LastSeen.Before(oldestTime) {
					oldestKey = k
					oldestTime = v.LastSeen
					first = false
				}
			}
			if oldestKey != "" {
				delete(fa.flows, oldestKey)
			}
		}
		fa.mu.Unlock()
	}
}

func xavierInit(in, out int) []float64 {
	scale := math.Sqrt(2.0 / float64(in+out))
	w := make([]float64, in*out)
	for i := range w {
		w[i] = randNormLocal() * scale
	}
	return w
}

func randNormLocal() float64 {
	buf := make([]byte, 8)
	rand.Read(buf)
	u1 := float64(binary.LittleEndian.Uint32(buf[:4]))/float64(1<<32) + 1e-10
	u2 := float64(binary.LittleEndian.Uint32(buf[4:]))/float64(1<<32) + 1e-10
	return math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
}
