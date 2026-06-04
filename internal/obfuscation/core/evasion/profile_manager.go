package evasion

import (
	"fmt"
	"regexp"
	"sync"
	"time"
	"whispera/internal/obfuscation/core/types"
)

type ProfileManager struct {
	profiles map[string]*types.TrafficProfile
	active   string
	mutex    sync.RWMutex
}

func NewProfileManager() *ProfileManager {
	return &ProfileManager{
		profiles: make(map[string]*types.TrafficProfile),
	}
}

func (pm *ProfileManager) AddProfile(name string, profile *types.TrafficProfile) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	profile.Name = name
	pm.profiles[name] = profile
}

func (pm *ProfileManager) GetProfile(name string) (*types.TrafficProfile, bool) {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	profile, exists := pm.profiles[name]
	return profile, exists
}

func (pm *ProfileManager) SetActiveProfile(name string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if _, exists := pm.profiles[name]; !exists {
		return fmt.Errorf("profile %s not found", name)
	}

	pm.active = name
	return nil
}

func (pm *ProfileManager) GetActiveProfile() string {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	return pm.active
}

func (pm *ProfileManager) ListProfiles() []string {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	names := make([]string, 0, len(pm.profiles))
	for name := range pm.profiles {
		names = append(names, name)
	}
	return names
}

func (pm *ProfileManager) RemoveProfile(name string) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if _, exists := pm.profiles[name]; !exists {
		return fmt.Errorf("profile %s not found", name)
	}

	delete(pm.profiles, name)
	if pm.active == name {
		pm.active = ""
	}
	return nil
}

func (pm *ProfileManager) UpdateProfile(name string, profile *types.TrafficProfile) error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if _, exists := pm.profiles[name]; !exists {
		return fmt.Errorf("profile %s not found", name)
	}

	profile.Name = name
	pm.profiles[name] = profile
	return nil
}

func (pm *ProfileManager) GetProfileStats() map[string]*ProfileStats {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	stats := make(map[string]*ProfileStats)
	for name, profile := range pm.profiles {
		stats[name] = &ProfileStats{
			Name:       name,
			Type:       profile.Type,
			IsActive:   name == pm.active,
			CreatedAt:  profile.CreatedAt,
			LastUsed:   profile.LastUsed,
			UsageCount: int64(profile.UsageCount),
		}
	}
	return stats
}

type ProfileStats struct {
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	IsActive   bool      `json:"is_active"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsed   time.Time `json:"last_used"`
	UsageCount int64     `json:"usage_count"`
}

type ProtocolProfile struct {
	Name        string
	Regex       *regexp.Regexp
	MinSize     int
	MaxSize     int
	CommonSizes []int
	Timing      TimingProfile
	Headers     map[string]string
	Fingerprint FingerprintProfile
}

type TimingProfile struct {
	MinInterval int
	MaxInterval int
	BurstProb   float64
	BurstMin    int
	BurstMax    int
	PauseProb   float64
	PauseMin    int
	PauseMax    int
	RTT         int64
	Jitter      int64
}

type FingerprintProfile struct {
	JA3        string
	JA4        string
	JA4S       string
	HTTP2      HTTP2Fingerprint
	QUIC       QUICFingerprint
	Behavioral BehavioralProfile

	PacketSizePatterns []int
	TimingPatterns     []int64
	EntropyProfile     EntropyProfile

	ObfuscationLevel   int
	AntiAnalysis       bool
	StatisticalMasking bool

	MLResistance       bool
	AdaptiveEvasion    bool
	ReinforcementRL    bool
	ContextAwareness   bool
	ThreatIntelligence bool

	WebsiteFingerprintDefense WebsiteFingerprintDefense
	TrafficObfuscation        TrafficObfuscation
	ProtocolMasquerading      ProtocolMasquerading
}

type HTTP2Fingerprint struct {
	Settings     map[string]int
	HeaderOrder  []string
	WindowSize   uint32
	StreamCount  uint32
	PingInterval time.Duration
}

type QUICFingerprint struct {
	Version         uint32
	TransportParams map[string]interface{}
	ConnectionID    []byte
	StreamID        uint32
	CWND            uint32
}

type BehavioralProfile struct {
	ThinkTime     time.Duration
	BurstPattern  string
	SessionLength time.Duration
	IdleTime      time.Duration

	HumanLikePatterns bool
	AdaptiveLearning  bool
	ReinforcementRL   bool

	InteractionPatterns []string
	DeviceFingerprint   string
	ContextAwareness    bool
}

type EntropyProfile struct {
	TargetEntropy    float64
	EntropyVariance  float64
	AntiEntropy      bool
	StatisticalNoise float64
}

type WebsiteFingerprintDefense struct {
	Enabled              bool
	PaddingStrategy      string
	TimingObfuscation    bool
	SizeObfuscation      bool
	DirectionObfuscation bool
	CoverTraffic         bool
	CoverProbability     float64
	CoverSize            int
	CoverInterval        time.Duration
}

type TrafficObfuscation struct {
	Enabled             bool
	MasqueradingType    string
	ObfuscationLevel    int
	AdaptiveObfuscation bool
	StatisticalMasking  bool
	EntropyAdjustment   bool
	TimingRandomization bool
	SizeRandomization   bool
	TargetService       string
}

type ProtocolMasquerading struct {
	Enabled           bool
	TargetProtocol    string
	TargetService     string
	MasqueradingLevel int
	HeaderSpoofing    bool
	BehavioralMimicry bool
	TimingMimicry     bool
	SizeMimicry       bool
	AdaptiveMimicry   bool
	MLResistance      bool
}

type FTEProfileManager struct {
	profiles map[string]*ProtocolProfile
	active   string
	mutex    sync.RWMutex
}
