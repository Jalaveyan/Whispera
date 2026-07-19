package tunnel

import (
	"context"
	"time"
)

type rotationManager struct {
	m *Manager

	rekeyTicker *time.Ticker
	rekeyCancel context.CancelFunc

	currentSNI string
}

func newRotationManager(m *Manager) *rotationManager {
	return &rotationManager{m: m}
}
