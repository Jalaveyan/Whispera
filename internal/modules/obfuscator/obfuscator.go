package obfuscator

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/obfuscation"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

const (
	ModuleName    = "obfuscation.engine"
	ModuleVersion = "2.0.0"
)

type Config struct {
	DefaultProfile   string
	BehavioralProfile string
	ThreatLevel      int
	EnableML         bool
	EnableFTE        bool
	WorkerCount      int

	EnableJitter             bool
	EnableResidentialMimicry bool
	ConnectionBurstLimit     int
	JitterMinMs              int
	JitterMaxMs              int
}

func DefaultConfig() *Config {
	return &Config{
		DefaultProfile: "default",
		ThreatLevel:    5,
		EnableML:       true,
		EnableFTE:      true,
		WorkerCount:    4,
		EnableJitter:             true,
		EnableResidentialMimicry: true,
		ConnectionBurstLimit:     10,
		JitterMinMs:              50,
		JitterMaxMs:              300,
	}
}

func (c *Config) Validate() error {
	if c.ThreatLevel < 0 || c.ThreatLevel > 10 {
		c.ThreatLevel = 5
	}
	return nil
}

type Engine struct {
	*base.Module
	config  *Config
	manager *obfuscation.IntegrationManager
	mu      sync.RWMutex

	currentProfile string
	threatLevel    int
	jitterRand      *rand.Rand
	lastConnTime    time.Time
	connCountWindow int
	windowStart     time.Time
}

func New(cfg *Config) (*Engine, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	manager := obfuscation.NewIntegrationManagerWithOptions(cfg.EnableML, cfg.EnableFTE)

	e := &Engine{
		Module:         base.NewModule(ModuleName, ModuleVersion, nil),
		config:         cfg,
		manager:        manager,
		currentProfile: cfg.DefaultProfile,
		threatLevel:    cfg.ThreatLevel,
	}

	if cfg.BehavioralProfile != "" {
		if err := manager.GetMarionetteAdapter().GetCore().SetBehavioralProfile(cfg.BehavioralProfile); err != nil {
			return nil, fmt.Errorf("obfuscator: behavioral profile %q: %w", cfg.BehavioralProfile, err)
		}
	}

	return e, nil
}

func (e *Engine) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := e.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if obfsCfg, ok := cfg.(*Config); ok {
		e.config = obfsCfg
	}

	if err := e.SetProfile(e.config.DefaultProfile); err != nil {
		_ = e.SetProfile("default")
	}
	e.SetThreatLevel(e.config.ThreatLevel)

	return nil
}

func (e *Engine) Start() error {
	if err := e.Module.Start(); err != nil {
		return err
	}

	e.SetHealthy(true, fmt.Sprintf("Active Profile: %s, Threat Level: %d", e.currentProfile, e.threatLevel))

	e.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"profile":      e.currentProfile,
		"threat_level": e.threatLevel,
		"ml_enabled":   e.config.EnableML,
		"fte_enabled":  e.config.EnableFTE,
	})

	return nil
}

func (e *Engine) Stop() error {
	e.PublishEvent(events.EventTypeModuleStopped, nil)
	return e.Module.Stop()
}

func (e *Engine) Process(data []byte, direction interfaces.Direction) ([]byte, time.Duration, error) {
	e.UpdateActivity()
	var jitterDelay time.Duration
	if direction == interfaces.DirectionOutbound && e.config.EnableJitter {
		jitterDelay = e.calculateJitter()
	}

	dirStr := "outbound"
	if direction == interfaces.DirectionInbound {
		dirStr = "inbound"
	}
	processed, delay, err := e.manager.ProcessTraffic(data, dirStr)
	if err != nil {
		return data, 0, err
	}
	totalDelay := delay + jitterDelay
	return processed, totalDelay, nil
}

func (e *Engine) calculateJitter() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.jitterRand == nil {
		e.jitterRand = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	now := time.Now()
	if e.config.ConnectionBurstLimit > 0 {
		if now.Sub(e.windowStart) > time.Second {
			e.windowStart = now
			e.connCountWindow = 0
		}
		e.connCountWindow++
		if e.connCountWindow > e.config.ConnectionBurstLimit {
			extraDelay := time.Duration(e.connCountWindow-e.config.ConnectionBurstLimit) * 100 * time.Millisecond
			return extraDelay
		}
	}

	minMs := e.config.JitterMinMs
	maxMs := e.config.JitterMaxMs
	if minMs <= 0 {
		minMs = 50
	}
	if maxMs <= minMs {
		maxMs = minMs + 250
	}

	if e.config.EnableResidentialMimicry && e.jitterRand.Float64() < 0.05 {
		return time.Duration(500+e.jitterRand.Intn(1500)) * time.Millisecond
	}

	jitterMs := minMs + e.jitterRand.Intn(maxMs-minMs)
	return time.Duration(jitterMs) * time.Millisecond
}

func (e *Engine) SetProfile(name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.manager.SetProfile(name); err != nil {
		return err
	}

	e.currentProfile = name
	e.SetHealthy(true, fmt.Sprintf("Profile: %s", name))

	e.PublishEvent("obfuscation.profile_changed", map[string]interface{}{
		"new_profile": name,
	})

	return nil
}

func (e *Engine) GetProfile() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.currentProfile
}

func (e *Engine) SetThreatLevel(level int) {
	if level < 0 {
		level = 0
	}
	if level > 10 {
		level = 10
	}

	e.mu.Lock()
	e.threatLevel = level
	e.mu.Unlock()

	isStrict := level >= 8
	e.manager.SetStrict(isStrict)

	e.PublishEvent("obfuscation.threat_level_changed", map[string]interface{}{
		"threat_level": level,
		"strict_mode":  isStrict,
	})
}

func (e *Engine) SetRealityKey(key string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.manager.SetRealityKey(key)
}

func (e *Engine) GetStats() interfaces.ObfuscationStats {
	metrics := e.manager.GetPerformanceMetrics()
	var pkts, bytes uint64
	var avgLat time.Duration

	if sys, ok := metrics["system"].(map[string]interface{}); ok {
		if p, ok := sys["packets_processed"].(uint64); ok {
			pkts = p
		} else if p, ok := sys["packets_processed"].(int64); ok {
			pkts = uint64(p)
		}

		if latStr, ok := sys["average_latency"].(string); ok {
			avgLat, _ = time.ParseDuration(latStr)
		}
	}

	if traffic, ok := metrics["traffic"].(map[string]interface{}); ok {
		if b, ok := traffic["total_bytes"].(int64); ok {
			bytes = uint64(b)
		}
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	return interfaces.ObfuscationStats{
		PacketsProcessed: pkts,
		BytesProcessed:   bytes,
		AvgProcessTime:   avgLat,
		ProfileName:      e.currentProfile,
		ThreatLevel:      e.threatLevel,
	}
}

func (e *Engine) HealthCheck() interfaces.HealthStatus {
	status := e.Module.HealthCheck()

	internalHealth := e.manager.GetHealthStatus()

	status.Details["profile"] = e.currentProfile
	status.Details["threat_level"] = e.threatLevel
	status.Details["internal_modules"] = internalHealth

	return status
}

func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
