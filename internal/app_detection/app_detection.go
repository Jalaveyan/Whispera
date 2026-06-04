package app_detection

import (
	"sync"
	"time"
)

type AppDetector struct {
	mu           sync.RWMutex
	runningApps  map[string]bool
	scanInterval time.Duration
	stopChan     chan struct{}
	scanning     bool
}

func NewAppDetector() *AppDetector {
	return &AppDetector{
		runningApps:  make(map[string]bool),
		scanInterval: 5 * time.Second,
		stopChan:     make(chan struct{}),
	}
}
