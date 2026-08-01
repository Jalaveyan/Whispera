package manager

import (
	"github.com/nekoskin/whispera/core/config"
	"net"
	"sync"
)

type Manager struct {
	mu        sync.RWMutex
	listeners map[string]net.Listener

	startCallback func(config.InboundConfig) error
	stopCallback  func(string) error
}

func New() *Manager {
	return &Manager{
		listeners: make(map[string]net.Listener),
	}
}

func (m *Manager) SetCallbacks(start func(config.InboundConfig) error, stop func(string) error) {
	m.startCallback = start
	m.stopCallback = stop
}

var Global *Manager

func init() {
	Global = New()
}
