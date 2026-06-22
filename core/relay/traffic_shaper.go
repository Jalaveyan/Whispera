package relay

import "time"

type TrafficShaper struct {
	lastCheck  time.Time
	bytesSince int

	targetRate float64
	minPadding int
	maxPadding int

	totalBytes uint64
}

func NewTrafficShaper(targetRateMBps float64) *TrafficShaper {
	return &TrafficShaper{
		lastCheck:  time.Now(),
		targetRate: targetRateMBps * 1024 * 1024,
		minPadding: 128,
		maxPadding: 1400,
	}
}

func (ts *TrafficShaper) Update(n int) int {
	now := time.Now()
	dt := now.Sub(ts.lastCheck).Seconds()

	ts.bytesSince += n
	ts.totalBytes += uint64(n)

	if dt < 0.05 {
		return 0
	}

	currentRate := float64(ts.bytesSince) / dt

	ts.lastCheck = now
	ts.bytesSince = 0

	if currentRate < ts.targetRate {
		needed := (ts.targetRate * dt) - float64(n)

		if needed > float64(ts.minPadding) {
			pad := int(needed)
			if pad > ts.maxPadding {
				pad = ts.maxPadding
			}
			return pad
		}
	}

	return 0
}
