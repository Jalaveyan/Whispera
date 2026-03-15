package fte

import (
	"fmt"
	"sync"
	"time"

	"whispera/internal/obfuscation/core/types"
)

type FTE struct {
	profiles map[string]*ProtocolProfile
	active   string
	state    *ProtocolState
	mutex    sync.RWMutex
	mlSystem types.UnifiedMLSystemInterface

	reinforcementLearning *ReinforcementLearning
	effectivenessTracker  *EffectivenessTracker
	coverTraffic          []byte
	adaptiveProfiles      map[string]*AdaptiveProfile

	rotationEnabled    bool
	rotationInterval   time.Duration
	rotationBytes      uint64
	lastRotationTime   time.Time
	bytesSinceRotation uint64
	rotationProfiles   []string
}

func NewFTE() *FTE {
	fte := &FTE{
		profiles:              make(map[string]*ProtocolProfile),
		state:                 &ProtocolState{},
		mlSystem:              nil,
		reinforcementLearning: NewReinforcementLearning(),
		effectivenessTracker:  NewEffectivenessTracker(),
		adaptiveProfiles:      make(map[string]*AdaptiveProfile),
		rotationProfiles:      []string{},
		lastRotationTime:      time.Now(),
	}

	fte.initProfiles()
	return fte
}

func (fte *FTE) initProfiles() {
	fte.loadRealTrafficData("fixed_traffic_data.csv")
	fte.addRussianServiceProfiles()
	fte.addModernProfiles()
	fte.addSocialProfiles()
	fte.addRussianMessengerProfiles()
}

func isFTETLSHandshake(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	contentType := data[0]
	majorVersion := data[1]
	minorVersion := data[2]

	isTLSContentType := contentType == 0x16 || contentType == 0x14 || contentType == 0x15
	isValidVersion := majorVersion == 0x03 && (minorVersion >= 0x01 && minorVersion <= 0x04)

	return isTLSContentType && isValidVersion
}

func (fte *FTE) Transform(data []byte) ([]byte, error) {
	fte.mutex.RLock()
	active := fte.active
	profile := fte.profiles[active]
	fte.mutex.RUnlock()

	if active == "" || profile == nil {
		return data, nil
	}

	targetSize := fte.calculateTargetSize(profile)
	obfuscated := fte.resizeToTarget(data, targetSize)
	formatted := fte.applyFormat(obfuscated, profile)

	formatted = fte.applyTimingObfuscation(formatted)

	fte.mutex.Lock()
	fte.updateState(targetSize)
	fte.mutex.Unlock()

	if fte.reinforcementLearning != nil {
		state := fte.GetProtocolState()
		if state == "" {
			state = "connected"
		}
		action := fte.reinforcementLearning.SelectAction(state)
		formatted = fte.applyReinforcementAction(formatted, action)
	}

	formatted, _ = fte.ApplyRealDPIEvasion(formatted, active)

	switch active {
	case "vk":
		formatted = fte.applyVKBehavioralPatterns(formatted)
	case ProfileYandexFTE:
		formatted = fte.applyYandexBehavioralPatterns(formatted)
	case ProfileMailruFTE:
		formatted = fte.applyMailruBehavioralPatterns(formatted)
	}

	return formatted, nil
}

func (f *FTE) ProcessPacket(data []byte, direction string) ([]byte, time.Duration, error) {
	if f == nil {
		return data, 0, fmt.Errorf("FTE not initialized")
	}

	processed, err := f.Transform(data)
	if err != nil {
		return data, 0, err
	}

	var delay time.Duration
	if len(processed) > 512 {
		delay = f.generateRealisticDelay(direction)
	}
	return processed, delay, nil
}

func (fte *FTE) SetMLSystem(mlSystem types.UnifiedMLSystemInterface) {
	fte.mutex.Lock()
	defer fte.mutex.Unlock()
	fte.mlSystem = mlSystem
}

func (fte *FTE) addProfile(name string, profile *ProtocolProfile) {
	fte.profiles[name] = profile
}

func (fte *FTE) SetActiveProfile(name string) error {
	fte.mutex.Lock()
	defer fte.mutex.Unlock()

	if _, exists := fte.profiles[name]; exists {
		fte.active = name
		fte.state = &ProtocolState{}
		return nil
	}
	return fmt.Errorf("profile %s not found", name)
}

func (fte *FTE) EnableRotation(interval time.Duration, bytes uint64, profiles []string) {
	fte.mutex.Lock()
	defer fte.mutex.Unlock()
	fte.rotationEnabled = true
	fte.rotationInterval = interval
	fte.rotationBytes = bytes
	fte.rotationProfiles = profiles
	if len(profiles) > 0 {
		fte.active = profiles[0]
	}
}

func (fte *FTE) RotateProfile() {
	if len(fte.rotationProfiles) < 2 {
		return
	}

	currentIndex := -1
	for i, name := range fte.rotationProfiles {
		if name == fte.active {
			currentIndex = i
			break
		}
	}

	nextIndex := (currentIndex + 1) % len(fte.rotationProfiles)
	nextProfile := fte.rotationProfiles[nextIndex]

	fte.active = nextProfile
	fte.state = &ProtocolState{}
	fte.lastRotationTime = time.Now()
	fte.bytesSinceRotation = 0
}

func (fte *FTE) updateState(size int) {
	fte.state.MessageCount++
	fte.state.MessageSizes = append(fte.state.MessageSizes, size)
	if len(fte.state.MessageSizes) > 100 {
		fte.state.MessageSizes = fte.state.MessageSizes[1:]
	}

	if fte.rotationEnabled {
		fte.bytesSinceRotation += uint64(size)
		shouldRotate := false

		if fte.rotationInterval > 0 && time.Since(fte.lastRotationTime) > fte.rotationInterval {
			shouldRotate = true
		}
		if fte.rotationBytes > 0 && fte.bytesSinceRotation > fte.rotationBytes {
			shouldRotate = true
		}

		if shouldRotate {
			fte.RotateProfile()
		}
	}

	profile := fte.profiles[fte.active]
	if profile != nil {
		timing := profile.Timing
		if !fte.state.InBurst && fte.state.MessageCount%10 == 0 {
			if timing.BurstProb > 0 && secureRandFloat64() < timing.BurstProb {
				fte.state.InBurst = true
				fte.state.BurstCount = timing.BurstMin + (fte.state.MessageCount % (timing.BurstMax - timing.BurstMin))
				fte.state.BurstStart = int64(fte.state.MessageCount)
			}
		}
		if fte.state.InBurst && fte.state.BurstCount <= 0 {
			fte.state.InBurst = false
		}
		if !fte.state.TypingPause && timing.PauseProb > 0 && secureRandFloat64() < timing.PauseProb {
			fte.state.TypingPause = true
			fte.state.PauseStart = int64(fte.state.MessageCount)
		}
	}
}

func (fte *FTE) GetHeaders() map[string]string {
	fte.mutex.RLock()
	defer fte.mutex.RUnlock()
	if fte.active == "" || fte.profiles[fte.active] == nil {
		return map[string]string{}
	}
	headers := make(map[string]string)
	for k, v := range fte.profiles[fte.active].Headers {
		headers[k] = v
	}
	return headers
}

func (fte *FTE) GetProtocolState() string {
	fte.mutex.RLock()
	defer fte.mutex.RUnlock()
	if fte.state == nil || fte.state.ProtocolState == "" {
		return "idle"
	}
	return fte.state.ProtocolState
}

func (f *FTE) generateRealisticDelay(direction string) time.Duration {
	baseDelay := 10
	if direction == "outbound" {
		baseDelay = 20
	}
	variance := 0.3
	return f.generateRealisticTiming(baseDelay, variance)
}

func (fte *FTE) applyTimingObfuscation(data []byte) []byte {
	return data
}
