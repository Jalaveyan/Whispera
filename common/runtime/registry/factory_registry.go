package registry

import (
	"github.com/nekoskin/whispera/common/runtime/interfaces"
	"sync"
)

type ModuleFactory func(cfg interface{}) (interfaces.Module, error)

type FactoryRegistry struct {
	mu        sync.RWMutex
	factories map[string]ModuleFactory
}

func NewFactoryRegistry() *FactoryRegistry {
	return &FactoryRegistry{
		factories: make(map[string]ModuleFactory),
	}
}

func (fr *FactoryRegistry) RegisterFactory(moduleType string, factory ModuleFactory) {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	fr.factories[moduleType] = factory
}

var GlobalFactoryRegistry = NewFactoryRegistry()
