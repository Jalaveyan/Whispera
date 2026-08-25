package relay

import (
	"runtime"
	"sync"
	"time"
)

const cpuBusyShare = 0.5

var cpuLoad struct {
	mu    sync.Mutex
	at    time.Time
	spent time.Duration
	busy  bool
}

func cpuBusy() bool {
	now := time.Now()

	cpuLoad.mu.Lock()
	defer cpuLoad.mu.Unlock()

	if !cpuLoad.at.IsZero() && now.Sub(cpuLoad.at) < time.Second {
		return cpuLoad.busy
	}

	spent := processCPU()
	if spent == 0 {
		return false
	}
	if !cpuLoad.at.IsZero() {
		wall := now.Sub(cpuLoad.at)
		cores := float64(runtime.GOMAXPROCS(0))
		cpuLoad.busy = float64(spent-cpuLoad.spent)/float64(wall)/cores >= cpuBusyShare
	}
	cpuLoad.at, cpuLoad.spent = now, spent
	return cpuLoad.busy
}
