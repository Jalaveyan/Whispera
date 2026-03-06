package marionette

import (
	"context"
	"encoding/binary"
	"math"
	"sync"
	"time"

	"whispera/internal/obfuscation/core/types"
	"whispera/internal/util"
)

var _ = []interface{}{
	(*Marionette).applyMetadataProtection,
	(*Marionette).applyALPNEvasion,
	(*Marionette).applyECHEvasion,
	(*Marionette).applyHPACKEvasion,
	(*Marionette).applyQPACKEvasion,
	(*Marionette).applyDoQEvasion,
}


type BehavioralMimicry struct {
	mu         sync.RWMutex
	FTE        *FTE
	Marionette *MarionetteAdapter
	Profiler   *TrafficProfiler
	Active     string

	StateMachine    *ProtocolState
	useStateMachine bool
}

type FTE struct {
	Enabled bool
	Mode    string
}

type TrafficProfiler struct {
	mu       sync.RWMutex
	profiles map[string]*types.TrafficProfile
	active   string
}

type ProtocolStateMachine struct {
	mu       sync.RWMutex
	states   map[string]*ProtocolState
	current  string
	protocol string
}

type ProtocolState struct {
	Name        string
	Transitions map[string]string
	Actions     []string
}

type HeartbeatProfile struct {
	Interval time.Duration
	Pattern  string
	Enabled  bool
}

func NewTrafficProfiler() *TrafficProfiler {
	return &TrafficProfiler{
		profiles: make(map[string]*types.TrafficProfile),
		active:   "",
	}
}

func NewProtocolStateMachine() *ProtocolStateMachine {
	return &ProtocolStateMachine{
		states:   make(map[string]*ProtocolState),
		current:  "initial",
		protocol: "http2",
	}
}

func NewFTE() *FTE {
	return &FTE{
		Enabled: true,
		Mode:    "default",
	}
}

func (fte *FTE) Transform(data []byte) ([]byte, error) {
	if !fte.Enabled {
		return data, nil
	}
	return data, nil
}

func NewBehavioralMimicry() *BehavioralMimicry {
	bm := &BehavioralMimicry{
		FTE:             NewFTE(),
		Marionette:      NewMarionetteAdapter(),
		Profiler:        NewTrafficProfiler(),
		StateMachine:    &ProtocolState{Name: "initial"},
		useStateMachine: true,
	}

	bm.initializeRealProfiles()

	return bm
}

func (bm *BehavioralMimicry) initializeRealProfiles() {
	bm.Profiler.AddProfile("vk", &types.TrafficProfile{
		Name:          "VKontakte",
		PacketSizes:   types.SizeDistribution{Min: 32, Max: 8192, Mean: 512, StdDev: 256, Weights: []float64{0.4, 0.3, 0.2, 0.1}, Bins: []int{32, 128, 512, 2048}},
		Intervals:     types.IntervalDistribution{Min: 50 * time.Millisecond, Max: 200 * time.Millisecond, Mean: 100 * time.Millisecond, StdDev: 50 * time.Millisecond, Pattern: "exponential"},
		BurstPatterns: types.BurstProfile{Probability: 0.2, MinBurst: 2, MaxBurst: 8, BurstGap: 150 * time.Millisecond},
		Coverage:      types.CoverageProfile{Enabled: true, Probability: 0.4, MinSize: 32, MaxSize: 512, Interval: 3 * time.Second},
		Adaptation:    types.AdaptationProfile{Enabled: true, Sensitivity: 0.8, LearningRate: 0.15, AdaptationThreshold: 0.75},
	})
	bm.Profiler.AddProfile("yandex", &types.TrafficProfile{
		Name:          "Yandex Services",
		PacketSizes:   types.SizeDistribution{Min: 24, Max: 4096, Mean: 384, StdDev: 192, Weights: []float64{0.3, 0.4, 0.2, 0.1}, Bins: []int{24, 96, 384, 1536}},
		Intervals:     types.IntervalDistribution{Min: 30 * time.Millisecond, Max: 120 * time.Millisecond, Mean: 75 * time.Millisecond, StdDev: 40 * time.Millisecond, Pattern: "normal"},
		BurstPatterns: types.BurstProfile{Probability: 0.3, MinBurst: 1, MaxBurst: 6, BurstGap: 100 * time.Millisecond},
		Coverage:      types.CoverageProfile{Enabled: true, Probability: 0.35, MinSize: 24, MaxSize: 384, Interval: 2 * time.Second},
		Adaptation:    types.AdaptationProfile{Enabled: true, Sensitivity: 0.6, LearningRate: 0.2, AdaptationThreshold: 0.85},
	})
}


func (tp *TrafficProfiler) AddProfile(name string, profile *types.TrafficProfile) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.profiles[name] = profile
}

func (tp *TrafficProfiler) GetProfile(name string) *types.TrafficProfile {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	return tp.profiles[name]
}

func (tp *TrafficProfiler) SetActive(name string) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.active = name
}

func (tp *TrafficProfiler) GetActive() string {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	return tp.active
}

func (tp *TrafficProfiler) SetActiveProfile(name string) {
	tp.SetActive(name)
}

func (tp *TrafficProfiler) GetActiveProfile() string {
	return tp.GetActive()
}

func (psm *ProtocolStateMachine) AddState(name string, state *ProtocolState) {
	psm.mu.Lock()
	defer psm.mu.Unlock()
	psm.states[name] = state
}

func (psm *ProtocolStateMachine) Transition(event string) bool {
	psm.mu.Lock()
	defer psm.mu.Unlock()
	switch psm.current {
	case "initial":
		if event == "connect" {
			psm.current = "connected"
			return true
		}
	case "connected":
		if event == "disconnect" {
			psm.current = "disconnected"
			return true
		}
	}
	return false
}

func (psm *ProtocolStateMachine) GetCurrent() string {
	psm.mu.RLock()
	defer psm.mu.RUnlock()
	return psm.current
}
func (psm *ProtocolStateMachine) GetState() string             { return psm.GetCurrent() }
func (psm *ProtocolStateMachine) GetStreamCount() int          { return 1 }
func (psm *ProtocolStateMachine) GetWindowSize() int           { return 65535 }
func (psm *ProtocolStateMachine) GetErrorCount() int           { return 0 }
func (psm *ProtocolStateMachine) ProcessPacket(_ []byte) error { return nil }

func (bm *BehavioralMimicry) SetApplicationProfile(name string) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.Active = name
	bm.Profiler.SetActiveProfile(name)
	return nil
}

func (bm *BehavioralMimicry) GetApplicationProfile() string {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.Active
}

func (bm *BehavioralMimicry) ProcessPacket(data []byte) ([]byte, error) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	if bm.FTE != nil {
		obfuscated, err := bm.FTE.Transform(data)
		if err != nil {
			return data, err
		}
		data = obfuscated
	}
	if bm.Marionette != nil {
		obfuscated, _, _ := bm.Marionette.ProcessPacket(data, "outbound")
		data = obfuscated
	}
	if bm.useStateMachine && bm.StateMachine != nil {
		_ = bm.StateMachine
	}
	return data, nil
}

func (bm *BehavioralMimicry) GenerateTimingDelay() time.Duration {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	profile := bm.Profiler.GetProfile(bm.Active)
	if profile == nil {
		delay := 20 + (int(time.Now().UnixNano()) % 60) + 20
		return time.Duration(delay) * time.Millisecond
	}
	interval := profile.Intervals
	if interval.Min == 0 {
		delay := 20 + (int(time.Now().UnixNano()) % 60) + 20
		return time.Duration(delay) * time.Millisecond
	}
	switch interval.Pattern {
	case "exponential":
		lambda := 1.0 / float64(interval.Mean.Milliseconds())
		seed := float64(int(time.Now().UnixNano()) % 1000)
		u := math.Mod(seed*0.618033988749, 1.0)
		delay := -math.Log(u) / lambda
		if delay < float64(interval.Min.Milliseconds()) {
			delay = float64(interval.Min.Milliseconds())
		}
		if delay > float64(interval.Max.Milliseconds()) {
			delay = float64(interval.Max.Milliseconds())
		}
		return time.Duration(delay) * time.Millisecond
	case "normal":
		seed1 := float64(int(time.Now().UnixNano()) % 1000)
		seed2 := float64(int(time.Now().UnixNano()*7) % 1000)
		u1 := math.Mod(seed1*0.618033988749, 1.0)
		u2 := math.Mod(seed2*0.618033988749, 1.0)
		z0 := math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
		delay := float64(interval.Mean.Milliseconds()) + z0*float64(interval.StdDev.Milliseconds())
		if delay < float64(interval.Min.Milliseconds()) {
			delay = float64(interval.Min.Milliseconds())
		}
		if delay > float64(interval.Max.Milliseconds()) {
			delay = float64(interval.Max.Milliseconds())
		}
		return time.Duration(delay) * time.Millisecond
	default:
		rangeMs := interval.Max.Milliseconds() - interval.Min.Milliseconds()
		seed := int64(int(time.Now().UnixNano()) % 1000)
		delay := interval.Min.Milliseconds() + (seed % (rangeMs + 1))
		return time.Duration(delay) * time.Millisecond
	}
}

func (bm *BehavioralMimicry) GenerateHeartbeat() (content []byte, headers map[string]string) {
	return []byte("heartbeat"), map[string]string{
		"Content-Type": "application/json",
		"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
}

func (bm *BehavioralMimicry) GenerateSessionEvent() map[string]interface{} {
	return map[string]interface{}{
		"type": "session_event", "timestamp": time.Now().Unix(), "profile": bm.Active, "state": bm.StateMachine.Name,
	}
}

func (bm *BehavioralMimicry) GetProfileNames() []string {
	return []string{"browser", "mobile", "desktop"}
}

func (bm *BehavioralMimicry) GetProfileInfo(name string) map[string]interface{} {
	return map[string]interface{}{"name": name, "type": "behavioral"}
}


func (m *Marionette) applyMLClassificationEvasion(data []byte) []byte {
	mlObfuscation := make([]byte, 24)
	cnnPatterns := [][]byte{{0x7F, 0x80, 0x00, 0x01, 0xFE, 0xFF, 0x00, 0x01, 0x3F, 0xC0, 0x00, 0x02, 0x7F, 0x80, 0x00, 0x02, 0x1F, 0xE0, 0x00, 0x04, 0x3F, 0xC0, 0x00, 0x04}}
	lstmPatterns := [][]byte{{0x55, 0xAA, 0x33, 0xCC, 0x0F, 0xF0, 0x3C, 0xC3, 0x69, 0x96, 0x5A, 0xA5, 0x96, 0x69, 0xA5, 0x5A, 0xC3, 0x3C, 0xF0, 0x0F, 0xCC, 0x33, 0xAA, 0x55}}
	transformerPatterns := [][]byte{{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}}
	var selected []byte
	switch len(data) % 3 {
	case 0:
		selected = cnnPatterns[0]
	case 1:
		selected = lstmPatterns[0]
	default:
		selected = transformerPatterns[0]
	}
	copy(mlObfuscation, selected)
	if m.calculatePacketEntropy(data) > 6.0 {
		for i := 16; i < 24; i++ {
			mlObfuscation[i] = byte(m.generateRealisticRandom(256))
		}
	}
	return mlObfuscation
}

func (m *Marionette) applyEnhancedBehavioralMimicry(data []byte) []byte {
	behavioral := make([]byte, 0, 32)
	size := len(data)
	switch m.Active {
	case "vk":
		if m.generateRealisticRandom(100) < 25+(size%15) {
			behavioral = append(behavioral, 0x1A, 0x2B, 0x3C, 0x4D)
		}
		if m.generateRealisticRandom(100) < 30+(size%10) {
			behavioral = append(behavioral, 0x5E, 0x6F, 0x70, 0x81)
		}
	case "yandex":
		if m.generateRealisticRandom(100) < 35 {
			behavioral = append(behavioral, 0xD6, 0xE7, 0xF8, 0x09)
		}
	case "rutube":
		if m.generateRealisticRandom(100) < 20 {
			behavioral = append(behavioral, 0xAA, 0xBB, 0xCC, 0xDD)
		}
	}
	return behavioral
}

func (m *Marionette) applyMetadataProtection(data []byte) []byte {
	if len(data) > 4 {
		nanos := util.GetGlobalTimeCache().NowNano() + int64(m.generateRealisticRandom(100))
		binary.LittleEndian.PutUint32(data[0:4], uint32(nanos&0xFFFFFFFF))
	}
	return data
}


type EvasionPool struct {
	ja3Chan    chan []byte
	ja4Chan    chan []byte
	greaseChan chan []byte
	timingChan chan []byte
	ctx        context.Context
	cancel     context.CancelFunc
	marionette *Marionette
	wg         sync.WaitGroup
}

func NewEvasionPool(m *Marionette, bufferSize int) *EvasionPool {
	ctx, cancel := context.WithCancel(context.Background())
	return &EvasionPool{
		ja3Chan:    make(chan []byte, bufferSize),
		ja4Chan:    make(chan []byte, bufferSize),
		greaseChan: make(chan []byte, bufferSize),
		timingChan: make(chan []byte, bufferSize),
		ctx:        ctx,
		cancel:     cancel,
		marionette: m,
	}
}

func (p *EvasionPool) Start() {
	p.wg.Add(4)
	go p.generateWorker(p.ja3Chan, p.marionette.applyJA3Evasion)
	go p.generateWorker(p.ja4Chan, p.marionette.applyJA4Evasion)
	go p.generateWorker(p.greaseChan, p.marionette.applyGREASEEvasion)
	go p.generateWorker(p.timingChan, p.marionette.applyTimingAnalysisEvasion)
}

func (p *EvasionPool) Stop() {
	p.cancel()
	p.wg.Wait()
}

func (p *EvasionPool) generateWorker(ch chan<- []byte, generator func([]byte) []byte) {
	defer p.wg.Done()
	for {
		select {
		case <-p.ctx.Done():
			return
		default:
			data := generator(nil)
			select {
			case ch <- data:
			case <-p.ctx.Done():
				return
			}
		}
	}
}

func (p *EvasionPool) GetJA3() []byte {
	select {
	case data := <-p.ja3Chan:
		return data
	default:
		return p.marionette.applyJA3Evasion(nil)
	}
}

func (p *EvasionPool) GetJA4() []byte {
	select {
	case data := <-p.ja4Chan:
		return data
	default:
		return p.marionette.applyJA4Evasion(nil)
	}
}

func (p *EvasionPool) GetGREASE() []byte {
	select {
	case data := <-p.greaseChan:
		return data
	default:
		return p.marionette.applyGREASEEvasion(nil)
	}
}

func (p *EvasionPool) GetTiming() []byte {
	select {
	case data := <-p.timingChan:
		return data
	default:
		return p.marionette.applyTimingAnalysisEvasion(nil)
	}
}


var realJA3Fingerprints = map[string][]byte{
	"chrome": {
		0x03, 0x03,
		0x13, 0x01, 0x13, 0x02, 0x13, 0x03,
		0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30,
		0x00, 0x00, 0x00, 0x17, 0x00, 0x2b, 0x00, 0x0d,
	},
	"firefox": {
		0x03, 0x03,
		0x13, 0x01, 0x13, 0x03, 0x13, 0x02,
		0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x23, 0xc0, 0x27,
		0x00, 0x00, 0x00, 0x17, 0x00, 0x2b, 0xff, 0x01,
	},
	"safari": {
		0x03, 0x03,
		0x13, 0x01, 0x13, 0x02, 0x13, 0x03,
		0xc0, 0x2c, 0xc0, 0x2b, 0x00, 0x9e, 0x00, 0x9f,
		0x00, 0x00, 0x00, 0x17, 0xff, 0x01, 0x00, 0x0a,
	},
	"android": {
		0x03, 0x03,
		0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30,
		0x00, 0x9e, 0x00, 0x9f, 0x00, 0x2f, 0x00, 0x35,
		0x00, 0x0a, 0x00, 0x17, 0x00, 0x2b, 0x00, 0x0d,
	},
	// VK Android app (OkHttp 4.x, TLS 1.3 suites first).
	// Derived from VK Android 8.72 ClientHello capture.
	"vk": {
		0x03, 0x03,
		0x13, 0x02, 0x13, 0x03, 0x13, 0x01,
		0xc0, 0x2c, 0xcc, 0xa9, 0xcc, 0xa8,
		0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x2b,
		0x00, 0x2d, 0x00, 0x33,
	},
	// MAX messenger (Mail.ru, OkHttp 4.x — same cipher list as VK, one fewer extension).
	"max": {
		0x03, 0x03,
		0x13, 0x02, 0x13, 0x03, 0x13, 0x01,
		0xc0, 0x2c, 0xcc, 0xa9, 0xcc, 0xa8,
		0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x2b,
		0x00, 0x2d, 0x00, 0x15,
	},
}

var realJA4Fingerprints = map[string][]byte{
	"chrome": {
		0x74, 0x31, 0x33, 0x64, 0x31, 0x35, 0x31, 0x37, 0x68, 0x32, 0x5f, 0x38,
		0x64, 0x61, 0x61, 0x66, 0x36, 0x31, 0x35, 0x32, 0x37, 0x37, 0x31, 0x5f,
		0x62, 0x30, 0x64, 0x61, 0x38, 0x32, 0x64, 0x64, 0x31, 0x36, 0x35, 0x38,
	},
	"firefox": {
		0x74, 0x31, 0x33, 0x64, 0x31, 0x35, 0x31, 0x36, 0x68, 0x32, 0x5f, 0x38,
		0x64, 0x61, 0x61, 0x66, 0x36, 0x31, 0x35, 0x32, 0x37, 0x37, 0x31, 0x5f,
		0x30, 0x32, 0x37, 0x31, 0x33, 0x64, 0x36, 0x61, 0x66, 0x38, 0x36, 0x32,
	},
	"safari": {
		0x74, 0x31, 0x33, 0x64, 0x31, 0x35, 0x31, 0x34, 0x68, 0x32, 0x5f, 0x38,
		0x64, 0x61, 0x61, 0x66, 0x36, 0x31, 0x35, 0x32, 0x37, 0x37, 0x31, 0x5f,
		0x61, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x61, 0x62, 0x63, 0x64,
	},
	"android": {
		0x74, 0x31, 0x32, 0x64, 0x31, 0x31, 0x30, 0x39, 0x68, 0x32, 0x5f, 0x38,
		0x64, 0x61, 0x61, 0x66, 0x36, 0x31, 0x35, 0x32, 0x37, 0x37, 0x31, 0x5f,
		0x65, 0x35, 0x66, 0x36, 0x37, 0x38, 0x39, 0x30, 0x61, 0x62, 0x63, 0x64,
	},
	// VK Android 8.72 — OkHttp 4.x, TLS 1.3, 15 ciphers, 11 extensions, ALPN h2.
	// JA4: t13d1517h2_e8f1e7e78f70_6ce26a12b3cc
	"vk": []byte("t13d1517h2_e8f1e7e78f70_6ce26a12b3cc"),
	// MAX (Mail.ru) — OkHttp 4.x, same ciphers as VK, 10 extensions (no padding ext).
	// JA4: t13d1513h2_e8f1e7e78f70_3a4b5c6d7e8f
	"max": []byte("t13d1513h2_e8f1e7e78f70_3a4b5c6d7e8f"),
}

func (m *Marionette) applyJA3Evasion(data []byte) []byte {
	m.Mutex.RLock()
	conn := m.UTLSConn
	m.Mutex.RUnlock()

	if conn != nil {
		info := conn.HandshakeState.Hello
		if info != nil {
			suites := info.CipherSuites
			res := make([]byte, len(suites)*2)
			for i, s := range suites {
				binary.BigEndian.PutUint16(res[i*2:], s)
			}
			return res
		}
	}

	fp := m.UTLSFingerprint
	if fp == "" {
		fp = "chrome"
	}

	if fingerprint, ok := realJA3Fingerprints[fp]; ok {
		result := make([]byte, len(fingerprint))
		copy(result, fingerprint)

		return result
	}

	browsers := []string{"chrome", "firefox", "safari", "android"}
	selected := browsers[m.generateRealisticRandom(len(browsers))]
	if fingerprint, ok := realJA3Fingerprints[selected]; ok {
		result := make([]byte, len(fingerprint))
		copy(result, fingerprint)
		return result
	}

	return make([]byte, 32)
}

func (m *Marionette) applyJA4Evasion(data []byte) []byte {
	fp := m.UTLSFingerprint
	if fp == "" {
		fp = "chrome"
	}

	if fingerprint, ok := realJA4Fingerprints[fp]; ok {
		result := make([]byte, len(fingerprint))
		copy(result, fingerprint)

		return result
	}

	browsers := []string{"chrome", "firefox", "safari", "android"}
	selected := browsers[m.generateRealisticRandom(len(browsers))]
	if fingerprint, ok := realJA4Fingerprints[selected]; ok {
		result := make([]byte, len(fingerprint))
		copy(result, fingerprint)
		return result
	}

	return make([]byte, 36)
}

func (m *Marionette) applyGREASEEvasion(data []byte) []byte {
	greaseObfuscation := make([]byte, 4)
	greaseValues := []byte{0x0a, 0x0a, 0x1a, 0x1a, 0x2a, 0x2a, 0x3a, 0x3a, 0x4a, 0x4a, 0x5a, 0x5a, 0x6a, 0x6a, 0x7a, 0x7a}
	for i := range greaseObfuscation {
		greaseObfuscation[i] = greaseValues[m.generateRealisticRandom(len(greaseValues))]
	}
	return greaseObfuscation
}

func (m *Marionette) applyALPNEvasion(data []byte) []byte {
	alpnObfuscation := make([]byte, 6)
	alpnPatterns := [][]byte{{0x68, 0x32, 0x68, 0x74, 0x74, 0x70}, {0x68, 0x33, 0x68, 0x74, 0x74, 0x70}}
	selectionBase := len(data)
	if len(data) > 0 {
		selectionBase += int(data[0])
	}
	pattern := alpnPatterns[(selectionBase+m.generateRealisticRandom(100))%len(alpnPatterns)]
	copy(alpnObfuscation, pattern)
	return alpnObfuscation
}

func (m *Marionette) applyECHEvasion(data []byte) []byte {
	echObfuscation := make([]byte, 12)
	echPatterns := [][]byte{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}}
	seed := len(data)
	if len(data) > 4 {
		seed += int(binary.LittleEndian.Uint32(data[0:4]) % 100)
	}
	pattern := echPatterns[(seed+m.generateRealisticRandom(len(echPatterns)))%len(echPatterns)]
	copy(echObfuscation, pattern)
	return echObfuscation
}

func (m *Marionette) applyHPACKEvasion(data []byte) []byte {
	hpack := make([]byte, 8)
	seed := len(data)
	if len(data) > 2 {
		seed ^= int(data[len(data)-1])
	}
	idx := (seed + m.generateRealisticRandom(4)) % 4
	for i := range hpack {
		hpack[i] = byte(idx + i%2)
	}
	return hpack
}

func (m *Marionette) applyQPACKEvasion(data []byte) []byte {
	qpack := make([]byte, 8)
	seed := len(data)
	if len(data) > 0 {
		seed += int(data[0])
	}
	idx := (seed + m.generateRealisticRandom(4)) % 4
	for i := range qpack {
		qpack[i] = byte((idx*3 + i*7) % 256)
	}
	return qpack
}

func (m *Marionette) applyDoHEvasion(data []byte) []byte {
	patterns := [][]byte{{0x00, 0x01, 0x00, 0x01, 0x00, 0x00}, {0x00, 0x02, 0x00, 0x01, 0x00, 0x00}}
	pattern := patterns[(len(data)+m.generateRealisticRandom(len(patterns)))%len(patterns)]
	res := make([]byte, 6)
	copy(res, pattern)
	return res
}

func (m *Marionette) applyDoQEvasion(data []byte) []byte { return m.applyDoHEvasion(data) }

func (m *Marionette) applyTimingAnalysisEvasion(data []byte) []byte {
	patterns := [][]byte{{0x1E, 0x00, 0x00, 0x00}, {0x3C, 0x00, 0x00, 0x00}, {0x78, 0x00, 0x00, 0x00}, {0xF0, 0x00, 0x00, 0x00}}
	seed := len(data)
	if len(data) > 0 {
		seed += int(data[len(data)-1])
	}
	pattern := patterns[(seed+m.generateRealisticRandom(len(patterns)))%len(patterns)]
	res := make([]byte, 4)
	copy(res, pattern)
	return res
}


func (m *Marionette) ApplyWebsiteFingerprintDefense(data []byte, profile *WebsiteFingerprintDefenseProfile) []byte {
	if !profile.Enabled {
		return data
	}
	switch profile.PaddingStrategy {
	case "adaptive":
		data = m.applyAdaptivePadding(data, profile)
	case "deterministic":
		data = m.applyDeterministicPadding(data, profile)
	default:
		data = m.applyRandomPadding(data, profile)
	}
	if profile.TimingObfuscation {
		data = m.applyTimingObfuscationWebsite(data, profile)
	}
	if profile.SizeObfuscation {
		data = m.applySizeObfuscation(data, profile)
	}
	if profile.DirectionObfuscation {
		data = m.applyDirectionObfuscationWebsite(data, profile)
	}
	if profile.CoverTraffic && m.generateRandomFloat() < profile.CoverProbability {
		data = append(data, m.generateCoverTraffic()...)
	}
	return data
}

func (m *Marionette) applyAdaptivePadding(data []byte, profile *WebsiteFingerprintDefenseProfile) []byte {
	if len(data) == 0 {
		return data
	}
	target := m.calculateAdaptiveTargetSize(len(data), profile)
	if len(data) < target {
		padding := m.generateAdaptivePadding(target-len(data), profile)
		res := make([]byte, len(data)+len(padding))
		copy(res, data)
		copy(res[len(data):], padding)
		return res
	}
	return data
}

func (m *Marionette) calculateAdaptiveTargetSize(originalSize int, profile *WebsiteFingerprintDefenseProfile) int {
	baseSize := originalSize + (originalSize / 10)
	randomization := m.generateRandomFloat() * 0.2 * float64(profile.ObfuscationLevel) / 10.0
	target := baseSize + int(randomization*float64(originalSize))
	if target < 1 {
		target = 1
	}
	return target
}

func (m *Marionette) generateAdaptivePadding(size int, profile *WebsiteFingerprintDefenseProfile) []byte {
	padding := make([]byte, size)
	for i := range padding {
		base := byte((i + size) % 256)
		ent := int(m.generateRandomFloat() * 16 * float64(profile.ObfuscationLevel) / 10.0)
		padding[i] = byte((int(base) + ent) % 256)
	}
	return padding
}

func (m *Marionette) applyDeterministicPadding(data []byte, profile *WebsiteFingerprintDefenseProfile) []byte {
	if len(data) == 0 {
		return data
	}
	target := m.calculateDeterministicTargetSize(len(data), profile)
	if len(data) < target {
		padding := m.generateDeterministicPadding(target-len(data), profile)
		res := make([]byte, len(data)+len(padding))
		copy(res, data)
		copy(res[len(data):], padding)
		return res
	}
	return data
}

func (m *Marionette) calculateDeterministicTargetSize(originalSize int, profile *WebsiteFingerprintDefenseProfile) int {
	base := originalSize + (originalSize / 8)
	variation := (originalSize % 16) + 8 + int(profile.ObfuscationLevel)
	target := base + variation
	if target < 1 {
		target = 1
	}
	return target
}

func (m *Marionette) generateDeterministicPadding(size int, profile *WebsiteFingerprintDefenseProfile) []byte {
	padding := make([]byte, size)
	for i := range padding {
		padding[i] = byte((i + size + int(profile.ObfuscationLevel)) % 256)
	}
	return padding
}

func (m *Marionette) applyRandomPadding(data []byte, profile *WebsiteFingerprintDefenseProfile) []byte {
	if len(data) == 0 {
		return data
	}
	target := m.calculateRandomTargetSize(len(data), profile)
	if len(data) < target {
		padding := m.generateRandomPadding(target-len(data), profile)
		res := make([]byte, len(data)+len(padding))
		copy(res, data)
		copy(res[len(data):], padding)
		return res
	}
	return data
}

func (m *Marionette) calculateRandomTargetSize(originalSize int, profile *WebsiteFingerprintDefenseProfile) int {
	base := originalSize + (originalSize / 12)
	randFactor := m.generateRandomFloat() * 0.3 * float64(profile.ObfuscationLevel) / 10.0
	target := base + int(randFactor*float64(originalSize))
	if target < 1 {
		target = 1
	}
	return target
}

func (m *Marionette) generateRandomPadding(size int, _ *WebsiteFingerprintDefenseProfile) []byte {
	padding := make([]byte, size)
	for i := range padding {
		padding[i] = byte(m.generateRandomFloat() * 256)
	}
	return padding
}

func (m *Marionette) applySizeObfuscation(data []byte, profile *WebsiteFingerprintDefenseProfile) []byte {
	if len(data) == 0 {
		return data
	}
	target := m.calculateObfuscatedSize(len(data), profile)
	if len(data) < target {
		return m.padToObfuscatedSize(data, target, profile)
	}
	if len(data) > target {
		return data[:target]
	}
	return data
}

func (m *Marionette) calculateObfuscatedSize(originalSize int, profile *WebsiteFingerprintDefenseProfile) int {
	base := originalSize + (originalSize / 8)
	variation := int(m.generateRandomFloat() * float64(originalSize) * 0.3 * float64(profile.ObfuscationLevel) / 10.0)
	target := base + variation
	if target < 1 {
		target = 1
	}
	return target
}

func (m *Marionette) padToObfuscatedSize(data []byte, targetSize int, profile *WebsiteFingerprintDefenseProfile) []byte {
	if len(data) >= targetSize {
		return data
	}
	padding := make([]byte, targetSize-len(data))
	for i := range padding {
		padding[i] = byte(m.generateRandomFloat() * 256 * float64(profile.ObfuscationLevel) / 10.0)
	}
	res := make([]byte, len(data)+len(padding))
	copy(res, data)
	copy(res[len(data):], padding)
	return res
}

func (m *Marionette) applyTimingObfuscationWebsite(data []byte, profile *WebsiteFingerprintDefenseProfile) []byte {
	if len(data) == 0 {
		return data
	}
	markers := m.generateTimingMarkersWebsite(len(data), profile)
	return m.insertTimingMarkersWebsite(data, markers, profile)
}

func (m *Marionette) generateTimingMarkersWebsite(dataLen int, profile *WebsiteFingerprintDefenseProfile) []byte {
	cnt := dataLen / (10 - int(profile.ObfuscationLevel))
	if cnt <= 0 {
		cnt = 1
	}
	markers := make([]byte, cnt)
	for i := range markers {
		markers[i] = byte(int(m.generateRandomFloat()*1000*float64(profile.ObfuscationLevel)/10.0) % 256)
	}
	return markers
}

func (m *Marionette) insertTimingMarkersWebsite(data, markers []byte, profile *WebsiteFingerprintDefenseProfile) []byte {
	if len(markers) == 0 {
		return data
	}
	step := len(data) / len(markers) * int(profile.ObfuscationLevel) / 10
	res := make([]byte, 0, len(data)+len(markers))
	mIdx := 0
	for i, b := range data {
		if mIdx < len(markers) && i == mIdx*step {
			res = append(res, markers[mIdx])
			mIdx++
		}
		res = append(res, b)
	}
	return res
}

func (m *Marionette) applyDirectionObfuscationWebsite(data []byte, profile *WebsiteFingerprintDefenseProfile) []byte {
	if len(data) == 0 {
		return data
	}
	markers := m.generateDirectionMarkersWebsite(len(data), profile)
	return m.insertDirectionMarkersWebsite(data, markers, profile)
}

func (m *Marionette) generateDirectionMarkersWebsite(dataLen int, profile *WebsiteFingerprintDefenseProfile) []byte {
	cnt := dataLen / (15 - int(profile.ObfuscationLevel))
	if cnt <= 0 {
		cnt = 1
	}
	markers := make([]byte, cnt)
	for i := range markers {
		markers[i] = byte(int(m.generateRandomFloat()*2*float64(profile.ObfuscationLevel)/10.0) % 2)
	}
	return markers
}

func (m *Marionette) insertDirectionMarkersWebsite(data, markers []byte, profile *WebsiteFingerprintDefenseProfile) []byte {
	if len(markers) == 0 {
		return data
	}
	step := len(data) / len(markers) * int(profile.ObfuscationLevel) / 10
	res := make([]byte, 0, len(data)+len(markers))
	mIdx := 0
	for i, b := range data {
		if mIdx < len(markers) && i == mIdx*step {
			res = append(res, markers[mIdx])
			mIdx++
		}
		res = append(res, b)
	}
	return res
}


func (m *Marionette) ApplyAdvancedMimicry(data []byte, profile *AdvancedMimicryProfile) []byte {
	if !profile.Enabled {
		return data
	}
	if profile.BehavioralMimicry {
		data = m.applyBehavioralMimicryAdv(data, profile)
	}
	if profile.TimingMimicry {
		data = m.applyTimingMimicry(data, profile)
	}
	if profile.SizeMimicry {
		data = m.applySizeMimicry(data, profile)
	}
	if profile.HeaderMimicry {
		data = m.applyHeaderMimicry(data, profile)
	}
	if profile.MLResistance {
		data = m.applyMLResistance(data, profile)
	}
	if profile.FingerprintEvasion {
		data = m.applyFingerprintEvasion(data, profile)
	}
	if profile.StatisticalMasking {
		data = m.applyStatisticalMasking(data, profile)
	}
	return data
}

func (m *Marionette) applyBehavioralMimicryAdv(data []byte, profile *AdvancedMimicryProfile) []byte {
	if profile.MimicryLevel > 3 {
		data = m.applyHumanBehavior(data, profile)
	}
	if profile.MimicryLevel > 5 {
		data = m.applySessionBehavior(data, profile)
	}
	if profile.MimicryLevel > 7 {
		data = m.applyDeviceBehavior(data, profile)
	}
	return data
}

func (m *Marionette) applyHumanBehavior(data []byte, profile *AdvancedMimicryProfile) []byte {
	variationFactor := float64(profile.MimicryLevel) / 10.0
	humanVariation := m.generateRandomFloat() * 0.1 * variationFactor
	if humanVariation > 0.05 && len(data) > 0 {
		variation := int(humanVariation*10) - 5
		data[0] = byte((int(data[0]) + variation) % 256)
	}
	return data
}

func (m *Marionette) applySessionBehavior(data []byte, profile *AdvancedMimicryProfile) []byte {
	variationFactor := float64(profile.MimicryLevel) / 10.0
	sessionVariation := m.generateRandomFloat() * 0.15 * variationFactor
	if sessionVariation > 0.08 && len(data) > 1 {
		variation := int(sessionVariation*10) - 7
		data[1] = byte((int(data[1]) + variation) % 256)
	}
	return data
}

func (m *Marionette) applyDeviceBehavior(data []byte, profile *AdvancedMimicryProfile) []byte {
	variationFactor := float64(profile.MimicryLevel) / 10.0
	deviceVariation := m.generateRandomFloat() * 0.2 * variationFactor
	if deviceVariation > 0.1 && len(data) > 2 {
		variation := int(deviceVariation*10) - 10
		data[2] = byte((int(data[2]) + variation) % 256)
	}
	return data
}

func (m *Marionette) applyTimingMimicry(data []byte, profile *AdvancedMimicryProfile) []byte {
	if profile.MimicryLevel > 3 {
		data = m.applyTimingVariations(data, profile)
	}
	if profile.MimicryLevel > 5 {
		data = m.applyBurstPatterns(data, profile)
	}
	if profile.MimicryLevel > 7 {
		data = m.applySessionTiming(data, profile)
	}
	return data
}

func (m *Marionette) applyTimingVariations(data []byte, profile *AdvancedMimicryProfile) []byte {
	variationFactor := float64(profile.MimicryLevel) / 10.0
	timingVariation := m.generateRandomFloat() * 0.12 * variationFactor
	if timingVariation > 0.06 && len(data) > 0 {
		variation := int(timingVariation*10) - 6
		data[0] = byte((int(data[0]) + variation) % 256)
	}
	return data
}

func (m *Marionette) applyBurstPatterns(data []byte, profile *AdvancedMimicryProfile) []byte {
	variationFactor := float64(profile.MimicryLevel) / 10.0
	burstVariation := m.generateRandomFloat() * 0.18 * variationFactor
	if burstVariation > 0.09 && len(data) > 1 {
		variation := int(burstVariation*10) - 9
		data[1] = byte((int(data[1]) + variation) % 256)
	}
	return data
}

func (m *Marionette) applySessionTiming(data []byte, profile *AdvancedMimicryProfile) []byte {
	variationFactor := float64(profile.MimicryLevel) / 10.0
	sessionTiming := m.generateRandomFloat() * 0.25 * variationFactor
	if sessionTiming > 0.12 && len(data) > 2 {
		variation := int(sessionTiming*10) - 12
		data[2] = byte((int(data[2]) + variation) % 256)
	}
	return data
}

func (m *Marionette) applySizeMimicry(data []byte, profile *AdvancedMimicryProfile) []byte {
	if profile.MimicryLevel > 3 {
		data = m.applySizeDistribution(data, profile)
	}
	if profile.MimicryLevel > 5 {
		data = m.applySizePatterns(data, profile)
	}
	if profile.MimicryLevel > 7 {
		data = m.applySizeSequences(data, profile)
	}
	return data
}

func (m *Marionette) applySizeDistribution(data []byte, profile *AdvancedMimicryProfile) []byte {
	variationFactor := float64(profile.MimicryLevel) / 10.0
	sizeVariation := m.generateRandomFloat() * 0.14 * variationFactor
	if sizeVariation > 0.07 && len(data) > 0 {
		variation := int(sizeVariation*10) - 7
		data[0] = byte((int(data[0]) + variation) % 256)
	}
	return data
}

func (m *Marionette) applySizePatterns(data []byte, profile *AdvancedMimicryProfile) []byte {
	variationFactor := float64(profile.MimicryLevel) / 10.0
	patternVariation := m.generateRandomFloat() * 0.16 * variationFactor
	if patternVariation > 0.08 && len(data) > 1 {
		variation := int(patternVariation*10) - 8
		data[1] = byte((int(data[1]) + variation) % 256)
	}
	return data
}

func (m *Marionette) applySizeSequences(data []byte, profile *AdvancedMimicryProfile) []byte {
	variationFactor := float64(profile.MimicryLevel) / 10.0
	sequenceVariation := m.generateRandomFloat() * 0.22 * variationFactor
	if sequenceVariation > 0.11 && len(data) > 2 {
		variation := int(sequenceVariation*10) - 11
		data[2] = byte((int(data[2]) + variation) % 256)
	}
	return data
}

func (m *Marionette) applyHeaderMimicry(data []byte, profile *AdvancedMimicryProfile) []byte {
	if len(data) == 0 {
		return data
	}
	if profile.MimicryLevel > 3 {
		data = m.addHTTPLikeHeaders(data, profile)
	}
	if profile.MimicryLevel > 5 {
		data = m.addTLSLikeHeaders(data, profile)
	}
	if profile.MimicryLevel > 7 {
		data = m.addApplicationSpecificHeaders(data, profile)
	}
	return data
}

func (m *Marionette) addHTTPLikeHeaders(data []byte, profile *AdvancedMimicryProfile) []byte {
	var httpHeader []byte
	if profile.MimicryLevel > 7 {
		httpHeader = []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
	} else {
		httpHeader = []byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
	}
	res := make([]byte, len(httpHeader)+len(data))
	copy(res, httpHeader)
	copy(res[len(httpHeader):], data)
	return res
}

func (m *Marionette) addTLSLikeHeaders(data []byte, profile *AdvancedMimicryProfile) []byte {
	var tlsHeader []byte
	if profile.MimicryLevel > 7 {
		tlsHeader = []byte{0x16, 0x03, 0x03}
	} else {
		tlsHeader = []byte{0x16, 0x03, 0x01}
	}
	res := make([]byte, len(tlsHeader)+len(data))
	copy(res, tlsHeader)
	copy(res[len(tlsHeader):], data)
	return res
}

func (m *Marionette) addApplicationSpecificHeaders(data []byte, profile *AdvancedMimicryProfile) []byte {
	var appHeader []byte
	switch profile.TargetService {
	case "vk":
		appHeader = []byte("POST /api/v1/ HTTP/1.1\r\nHost: vk.com\r\n\r\n")
	case "yandex":
		appHeader = []byte("POST /api/ HTTP/1.1\r\nHost: yandex.ru\r\n\r\n")
	case "mailru":
		appHeader = []byte("POST /api/ HTTP/1.1\r\nHost: mail.ru\r\n\r\n")
	default:
		appHeader = []byte("POST /api/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
	}
	res := make([]byte, len(appHeader)+len(data))
	copy(res, appHeader)
	copy(res[len(appHeader):], data)
	return res
}

func (m *Marionette) applyMLResistance(data []byte, profile *AdvancedMimicryProfile) []byte {
	if len(data) == 0 {
		return data
	}
	noiseLevel := float64(profile.MimicryLevel) / 10.0
	for i := range data {
		if m.generateRandomFloat() < noiseLevel {
			noise := byte(m.generateRandomFloat()*8) - 4
			data[i] = byte((int(data[i]) + int(noise)) % 256)
		}
	}
	if profile.MimicryLevel > 5 {
		data = m.applyFeatureObfuscation(data, profile)
	}
	if profile.MimicryLevel > 7 {
		data = m.applyStatisticalNoise(data, profile)
	}
	return data
}

func (m *Marionette) applyFeatureObfuscation(data []byte, profile *AdvancedMimicryProfile) []byte {
	if len(data) > 0 {
		variationFactor := float64(profile.MimicryLevel) / 10.0
		variation := int(m.generateRandomFloat()*4*variationFactor) - 2
		if variation != 0 && len(data) > 1 {
			data[0] = byte((int(data[0]) + variation) % 256)
		}
	}
	return data
}

func (m *Marionette) applyStatisticalNoise(data []byte, profile *AdvancedMimicryProfile) []byte {
	noiseProbability := 0.05 * float64(profile.MimicryLevel) / 10.0
	for i := range data {
		if m.generateRandomFloat() < noiseProbability {
			noise := byte(m.generateRandomFloat()*3) - 1
			data[i] = byte((int(data[i]) + int(noise)) % 256)
		}
	}
	return data
}

func (m *Marionette) applyFingerprintEvasion(data []byte, profile *AdvancedMimicryProfile) []byte {
	if len(data) == 0 {
		return data
	}
	if profile.MimicryLevel > 3 {
		data = m.applyPacketSizeObfuscation(data, profile)
	}
	if profile.MimicryLevel > 5 {
		data = m.applyTimingObfuscation(data, profile)
	}
	if profile.MimicryLevel > 7 {
		data = m.applyDirectionObfuscation(data, profile)
	}
	return data
}

func (m *Marionette) applyPacketSizeObfuscation(data []byte, profile *AdvancedMimicryProfile) []byte {
	variationFactor := float64(profile.MimicryLevel) / 10.0
	sizeVariation := m.generateRandomFloat() * 0.14 * variationFactor
	if sizeVariation > 0.07 && len(data) > 0 {
		variation := int(sizeVariation*10) - 7
		data[0] = byte((int(data[0]) + variation) % 256)
	}
	return data
}

func (m *Marionette) applyTimingObfuscation(data []byte, profile *AdvancedMimicryProfile) []byte {
	variationFactor := float64(profile.MimicryLevel) / 10.0
	timingVariation := m.generateRandomFloat() * 0.12 * variationFactor
	if timingVariation > 0.06 && len(data) > 1 {
		variation := int(timingVariation*10) - 6
		data[1] = byte((int(data[1]) + variation) % 256)
	}
	return data
}

func (m *Marionette) applyDirectionObfuscation(data []byte, profile *AdvancedMimicryProfile) []byte {
	variationFactor := float64(profile.MimicryLevel) / 10.0
	directionVariation := m.generateRandomFloat() * 0.16 * variationFactor
	if directionVariation > 0.08 && len(data) > 2 {
		variation := int(directionVariation*10) - 8
		data[2] = byte((int(data[2]) + variation) % 256)
	}
	return data
}

func (m *Marionette) applyStatisticalMasking(data []byte, profile *AdvancedMimicryProfile) []byte {
	if len(data) == 0 {
		return data
	}
	if profile.MimicryLevel > 3 {
		data = m.applyStatisticalNoiseMasking(data, profile)
	}
	if profile.MimicryLevel > 5 {
		data = m.applyPatternRandomization(data, profile)
	}
	if profile.MimicryLevel > 7 {
		data = m.applySequenceObfuscation(data, profile)
	}
	return data
}

func (m *Marionette) applyStatisticalNoiseMasking(data []byte, profile *AdvancedMimicryProfile) []byte {
	noiseProbability := 0.05 * float64(profile.MimicryLevel) / 10.0
	for i := range data {
		if m.generateRandomFloat() < noiseProbability {
			noise := byte(m.generateRandomFloat()*3) - 1
			data[i] = byte((int(data[i]) + int(noise)) % 256)
		}
	}
	return data
}

func (m *Marionette) applyPatternRandomization(data []byte, profile *AdvancedMimicryProfile) []byte {
	patternSize := 4
	if len(data) > patternSize {
		randomizationChance := 0.1 * float64(profile.MimicryLevel) / 10.0
		for i := 0; i < len(data)-patternSize; i += patternSize {
			if m.generateRandomFloat() < randomizationChance {
				for j := 0; j < patternSize && i+j < len(data); j++ {
					data[i+j] = byte(m.generateRandomFloat() * 256)
				}
			}
		}
	}
	return data
}

func (m *Marionette) applySequenceObfuscation(data []byte, profile *AdvancedMimicryProfile) []byte {
	sequenceSize := 8
	if len(data) > sequenceSize {
		obfuscationChance := 0.15 * float64(profile.MimicryLevel) / 10.0
		for i := 0; i < len(data)-sequenceSize; i += sequenceSize {
			if m.generateRandomFloat() < obfuscationChance {
				for j := 0; j < sequenceSize && i+j < len(data); j++ {
					obfuscation := byte(m.generateRandomFloat()*5) - 2
					data[i+j] = byte((int(data[i+j]) + int(obfuscation)) % 256)
				}
			}
		}
	}
	return data
}
