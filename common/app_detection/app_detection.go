package app_detection

import (
	"time"
)

type AppDetector struct {
	runningApps  map[string]bool
	scanInterval time.Duration
	stopChan     chan struct{}
}

func NewAppDetector() *AppDetector {
	return &AppDetector{
		runningApps:  make(map[string]bool),
		scanInterval: 1 * time.Second,
		stopChan:     make(chan struct{}),
	}
}
