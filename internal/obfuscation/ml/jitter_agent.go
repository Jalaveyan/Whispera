package ml

import (
	"fmt"
	"math"
	mrand "math/rand"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/obfuscation/ml/gnet"
)

var jLog = func(format string, args ...interface{}) {
	fmt.Printf("[RL-JITTER] "+format+"\n", args...)
}

// JitterFractions — доля от базового интервала keepalive, добавляемая как ±jitter.
// 0.10 = ±10%, 0.70 = ±70%.
var JitterFractions = []float64{0.10, 0.20, 0.40, 0.70}

const (
	jStateSize    = 5
	jHidden1      = 10
	jHidden2      = 6
	jNumActions   = 4 // len(JitterFractions)
	jBufferSize   = 400
	jBatchSize    = 8
	jGamma        = 0.95
	jEpsilonStart = 0.40
	jEpsilonMin   = 0.05
	jEpsilonDecay = 0.98
	jTargetSync   = 20
	jTrainEvery   = 4
)

// JitterView — снимок состояния сети для агента джиттера.
type JitterView struct {
	RTTMs     float64
	MissedKAs int
	ErrorRate float64
}

// RLJitterAgent выбирает оптимальный уровень временно́го джиттера для keepalive.
//
// State (5): rtt_norm, missed_ka_norm, error_rate, hour_sin, hour_cos
// Actions: ±10% / ±20% / ±40% / ±70% от базового интервала
// Reward: стабильность соединения − штраф за высокий джиттер
//
// Высокий джиттер разрушает timing-анализ DPI, но увеличивает нагрузку.
// Агент учится балансировать между ними.
type RLJitterAgent struct {
	mu sync.RWMutex

	qNet   *gnet.GorgoniaNet
	target *gnet.GorgoniaNet

	buffer  []Experience
	bufIdx  int
	bufFull bool

	epsilon    float64
	stepCount  int64
	trainCount int64

	pendingState  []float64
	pendingAction int
}

func NewRLJitterAgent() *RLJitterAgent {
	a := &RLJitterAgent{
		buffer:        make([]Experience, jBufferSize),
		epsilon:       jEpsilonStart,
		pendingAction: -1,
	}
	a.qNet = gnet.New([]int{jStateSize, jHidden1, jHidden2, jNumActions})
	a.target = gnet.Clone(a.qNet)
	return a
}

func (a *RLJitterAgent) encodeState(v JitterView) []float64 {
	s := make([]float64, jStateSize)
	s[0] = math.Min(v.RTTMs/500.0, 1.0)
	s[1] = math.Min(float64(v.MissedKAs)/5.0, 1.0)
	s[2] = math.Min(v.ErrorRate, 1.0)
	hour := float64(time.Now().Hour()) + float64(time.Now().Minute())/60.0
	s[3] = math.Sin(2 * math.Pi * hour / 24.0)
	s[4] = math.Cos(2 * math.Pi * hour / 24.0)
	return s
}

// Decide возвращает долю джиттера (0.10–0.70).
// Применяется как: jitter = rand(-frac*base, +frac*base).
func (a *RLJitterAgent) Decide(v JitterView) float64 {
	state := a.encodeState(v)
	a.mu.Lock()
	defer a.mu.Unlock()

	var idx int
	if mrand.Float64() < a.epsilon {
		idx = mrand.Intn(jNumActions)
	} else {
		idx = dqnArgmax(a.qNet, state, jNumActions)
	}

	a.pendingState = state
	a.pendingAction = idx
	jLog("frac=±%.0f%% eps=%.2f", JitterFractions[idx]*100, a.epsilon)
	return JitterFractions[idx]
}

// RecordOutcome: quality=1 соединение стабильно, 0 — пропущен keepalive/обрыв.
func (a *RLJitterAgent) RecordOutcome(quality float64) {
	a.mu.Lock()
	state := a.pendingState
	action := a.pendingAction
	a.mu.Unlock()
	if state == nil || action < 0 {
		return
	}

	// Высокий джиттер стоит чуть дороже (0.05 * tier).
	jitterCost := float64(action) * 0.05
	reward := quality - jitterCost

	a.mu.Lock()
	a.buffer[a.bufIdx] = Experience{
		State: state, Action: action, Reward: reward,
		NextState: state, Done: quality < 0.1,
	}
	a.bufIdx = (a.bufIdx + 1) % jBufferSize
	if a.bufIdx == 0 {
		a.bufFull = true
	}
	a.epsilon = math.Max(jEpsilonMin, a.epsilon*jEpsilonDecay)
	step := atomic.AddInt64(&a.stepCount, 1)
	a.mu.Unlock()

	if step%jTrainEvery == 0 {
		go a.trainStep()
	}
	if step%jTargetSync == 0 {
		a.mu.Lock()
		a.target = gnet.Clone(a.qNet)
		a.mu.Unlock()
	}
}

func (a *RLJitterAgent) Epsilon() float64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.epsilon
}

func (a *RLJitterAgent) trainStep() {
	a.mu.RLock()
	batch, ok := sampleBatch(a.buffer, a.bufIdx, a.bufFull, jBatchSize)
	a.mu.RUnlock()
	if !ok {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	dqnTrainBatch(a.qNet, a.target, batch, jNumActions, jGamma, 0.001)
	atomic.AddInt64(&a.trainCount, 1)
}
