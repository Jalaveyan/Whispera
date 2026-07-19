package neural

import (
	"math"
	"sync"
	"time"
)

const (
	DPITypeNone         = 0
	DPITypeTSPURST      = 6
	DPITypeTSPUThrottle = 7
	DPITypeTSPUReplay   = 8
	DPITypeZombieTCP    = 9

	TSPUHistoryWindow  = 100
	TSPURSTThresholdMs = 10
)

type rstEvent struct {
	SNI       string
	TimeToRST time.Duration
	Timestamp time.Time
	Blocked   bool
}

type TSPUDetector struct {
	mu        sync.Mutex
	rstEvents []rstEvent
	rstIdx    int
	rstFull   bool
}

func NewTSPUDetector() *TSPUDetector {
	return &TSPUDetector{rstEvents: make([]rstEvent, TSPUHistoryWindow)}
}

func (d *TSPUDetector) RecordRST(sni string, timeToRST time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rstEvents[d.rstIdx] = rstEvent{
		SNI:       sni,
		TimeToRST: timeToRST,
		Timestamp: time.Now(),
		Blocked:   timeToRST < time.Duration(TSPURSTThresholdMs)*time.Millisecond,
	}
	d.rstIdx = (d.rstIdx + 1) % TSPUHistoryWindow
	if d.rstIdx == 0 {
		d.rstFull = true
	}
}

func (d *TSPUDetector) DetectTSPU() (dpiType int, confidence float64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	window := 5 * time.Minute
	size := d.rstIdx
	if d.rstFull {
		size = TSPUHistoryWindow
	}

	total, blocked := 0, 0
	for i := 0; i < size; i++ {
		ev := d.rstEvents[i]
		if now.Sub(ev.Timestamp) > window {
			continue
		}
		total++
		if ev.Blocked {
			blocked++
		}
	}
	if total >= 3 && float64(blocked)/float64(total) > 0.5 {
		return DPITypeTSPURST, math.Min(float64(blocked)/float64(total), 0.95)
	}
	return DPITypeNone, 0
}

func TSPUCountermeasure(dpiType int) string {
	switch dpiType {
	case DPITypeTSPURST, DPITypeTSPUReplay, DPITypeZombieTCP:
		return "grpc"
	case DPITypeTSPUThrottle:
		return "yadisk"
	default:
		return ""
	}
}
