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

var boLog = func(format string, args ...interface{}) {
	fmt.Printf("[RL-BACKOFF] "+format+"\n", args...)
}

// BackoffDelays — дискретный набор задержек переподключения.
var BackoffDelays = []time.Duration{
	1 * time.Second,
	3 * time.Second,
	8 * time.Second,
	20 * time.Second,
	60 * time.Second,
}

// BackoffErrType классифицирует причину отказа соединения.
type BackoffErrType int

const (
	BackoffErrUnknown BackoffErrType = 0
	BackoffErrTimeout BackoffErrType = 1
	BackoffErrTLS     BackoffErrType = 2
	BackoffErrRefused BackoffErrType = 3
)

const (
	boStateSize    = 5
	boHidden1      = 12
	boHidden2      = 8
	boNumActions   = 5 // len(BackoffDelays)
	boBufferSize   = 400
	boBatchSize    = 8
	boGamma        = 0.95
	boEpsilonStart = 0.40
	boEpsilonMin   = 0.05
	boEpsilonDecay = 0.98
	boTargetSync   = 20
	boTrainEvery   = 4
)

// BackoffView — контекст для выбора задержки переподключения.
type BackoffView struct {
	ConsecutiveFails    int
	LastErrType         BackoffErrType
	TimeSinceSuccessSec float64
}

// RLBackoffAgent выбирает оптимальную задержку перед повторным соединением через DQN.
//
// State (5): fails_norm, err_type_norm, time_since_success_norm, hour_sin, hour_cos
// Actions: 1s / 3s / 8s / 20s / 60s
// Reward: +1 при успехе (штраф за длинную задержку), −0.5 при повторном отказе
type RLBackoffAgent struct {
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

func NewRLBackoffAgent() *RLBackoffAgent {
	a := &RLBackoffAgent{
		buffer:        make([]Experience, boBufferSize),
		epsilon:       boEpsilonStart,
		pendingAction: -1,
	}
	a.qNet = gnet.New([]int{boStateSize, boHidden1, boHidden2, boNumActions})
	a.target = gnet.Clone(a.qNet)
	return a
}

func (a *RLBackoffAgent) encodeState(v BackoffView) []float64 {
	s := make([]float64, boStateSize)
	s[0] = math.Min(float64(v.ConsecutiveFails)/10.0, 1.0)
	s[1] = float64(v.LastErrType) / 3.0
	s[2] = math.Min(v.TimeSinceSuccessSec/600.0, 1.0) // 10 мин → 1.0
	hour := float64(time.Now().Hour()) + float64(time.Now().Minute())/60.0
	s[3] = math.Sin(2 * math.Pi * hour / 24.0)
	s[4] = math.Cos(2 * math.Pi * hour / 24.0)
	return s
}

// Decide возвращает задержку перед следующей попыткой переподключения.
func (a *RLBackoffAgent) Decide(v BackoffView) time.Duration {
	state := a.encodeState(v)
	a.mu.Lock()
	defer a.mu.Unlock()

	var idx int
	if mrand.Float64() < a.epsilon {
		idx = mrand.Intn(boNumActions)
	} else {
		idx = dqnArgmax(a.qNet, state, boNumActions)
	}

	a.pendingState = state
	a.pendingAction = idx
	boLog("delay=%v fails=%d err=%d eps=%.2f", BackoffDelays[idx], v.ConsecutiveFails, v.LastErrType, a.epsilon)
	return BackoffDelays[idx]
}

// RecordOutcome фиксирует результат попытки переподключения.
func (a *RLBackoffAgent) RecordOutcome(success bool) {
	a.mu.Lock()
	state := a.pendingState
	action := a.pendingAction
	a.mu.Unlock()
	if state == nil || action < 0 {
		return
	}

	var reward float64
	if success {
		// Короткая задержка + успех → лучшая награда.
		delayCost := float64(action) * 0.05
		reward = 1.0 - delayCost
	} else {
		reward = -0.5
	}

	a.mu.Lock()
	a.buffer[a.bufIdx] = Experience{
		State: state, Action: action, Reward: reward,
		NextState: state, Done: !success,
	}
	a.bufIdx = (a.bufIdx + 1) % boBufferSize
	if a.bufIdx == 0 {
		a.bufFull = true
	}
	a.epsilon = math.Max(boEpsilonMin, a.epsilon*boEpsilonDecay)
	step := atomic.AddInt64(&a.stepCount, 1)
	a.mu.Unlock()

	if step%boTrainEvery == 0 {
		go a.trainStep()
	}
	if step%boTargetSync == 0 {
		a.mu.Lock()
		a.target = gnet.Clone(a.qNet)
		a.mu.Unlock()
	}
}

// ClassifyErr переводит текст ошибки в BackoffErrType.
func ClassifyBackoffErr(errStr string) BackoffErrType {
	switch {
	case containsAny(errStr, "timeout", "deadline", "i/o timeout"):
		return BackoffErrTimeout
	case containsAny(errStr, "handshake", "certificate", "tls", "x509"):
		return BackoffErrTLS
	case containsAny(errStr, "refused", "no route", "unreachable"):
		return BackoffErrRefused
	default:
		return BackoffErrUnknown
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

func (a *RLBackoffAgent) Epsilon() float64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.epsilon
}

func (a *RLBackoffAgent) trainStep() {
	a.mu.RLock()
	batch, ok := sampleBatch(a.buffer, a.bufIdx, a.bufFull, boBatchSize)
	a.mu.RUnlock()
	if !ok {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	dqnTrainBatch(a.qNet, a.target, batch, boNumActions, boGamma, 0.001)
	atomic.AddInt64(&a.trainCount, 1)
}
