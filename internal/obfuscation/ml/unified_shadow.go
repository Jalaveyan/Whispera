package ml

import "sync"

var (
	shadowOnce        sync.Once
	shadowNet         *UnifiedNet
	shadowMu          sync.Mutex
	shadowChunkState  []float64
	shadowChunkAction int
	shadowAgree       int64
	shadowTotal       int64
)

func shadowInit() {
	shadowNet = NewUnifiedNet(UnifiedStateSize, 64, 32, map[string]int{"chunk": chunkNumActions})
}

func chunkViewToState(v ChunkView) []float64 {
	return UnifiedState{
		RTTMs: v.RTTMs / 100.0,
		UpBps: v.BytesUpSec / 1e6,
		DnBps: v.BytesDnSec / 1e6,
	}.Vec()
}

func shadowChunkDecide(v ChunkView, realIdx int) {
	shadowOnce.Do(shadowInit)
	state := chunkViewToState(v)
	greedy := argmax(shadowNet.QValues(state, "chunk"))
	shadowMu.Lock()
	shadowChunkState = state
	shadowChunkAction = realIdx
	shadowTotal++
	if greedy == realIdx {
		shadowAgree++
	}
	agree, total := shadowAgree, shadowTotal
	shadowMu.Unlock()
	if total%200 == 0 {
		chunkLog.Info("shadow chunk parity: %.1f%% (%d/%d) greedy=%d real=%d",
			100*float64(agree)/float64(total), agree, total, greedy, realIdx)
	}
}

func shadowChunkOutcome(reward float64) {
	if shadowNet == nil {
		return
	}
	shadowMu.Lock()
	state := shadowChunkState
	action := shadowChunkAction
	shadowMu.Unlock()
	if state == nil {
		return
	}
	shadowNet.Train(state, "chunk", action, reward, 0.001)
}
