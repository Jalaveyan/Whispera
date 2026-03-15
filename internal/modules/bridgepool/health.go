package bridgepool

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"sync"
	"time"
)

type HealthMonitor struct {
	registry      *Registry
	checkInterval time.Duration
	timeout       time.Duration
	stop          chan struct{}
	wg            sync.WaitGroup
	running       bool
	mu            sync.Mutex
}

func NewHealthMonitor(registry *Registry, checkInterval time.Duration) *HealthMonitor {
	return &HealthMonitor{
		registry:      registry,
		checkInterval: checkInterval,
		timeout:       5 * time.Second,
		stop:          make(chan struct{}),
	}
}

func (h *HealthMonitor) Start() {
	h.mu.Lock()
	if h.running {
		h.mu.Unlock()
		return
	}
	h.running = true
	h.stop = make(chan struct{})
	h.mu.Unlock()

	h.wg.Add(1)
	go h.loop()
	log.Println("[BridgePool] Health monitor started")
}

func (h *HealthMonitor) Stop() {
	h.mu.Lock()
	if !h.running {
		h.mu.Unlock()
		return
	}
	h.running = false
	h.mu.Unlock()

	close(h.stop)
	h.wg.Wait()
	log.Println("[BridgePool] Health monitor stopped")
}

func (h *HealthMonitor) loop() {
	defer h.wg.Done()

	ticker := time.NewTicker(h.checkInterval)
	defer ticker.Stop()

	h.checkAll()

	for {
		select {
		case <-ticker.C:
			h.checkAll()
		case <-h.stop:
			return
		}
	}
}

func (h *HealthMonitor) checkAll() {
	bridges := h.registry.GetAllBridges()
	if len(bridges) == 0 {
		return
	}

	log.Printf("[BridgePool] Checking health of %d bridges (lazy mode)", len(bridges))

	firstAlive := make(chan *BridgeInfo, 1)

	for _, bridge := range bridges {
		go func(b *BridgeInfo) {
			h.checkBridge(b)
			if b.IsAlive {
				select {
				case firstAlive <- b:
				default:
				}
			}
		}(bridge)
	}

	select {
	case first := <-firstAlive:
		log.Printf("[BridgePool] First alive bridge: %s (%dms) - continuing in background", first.ID, first.Latency)
	case <-time.After(h.timeout * 2):
		log.Printf("[BridgePool] No bridge responded within timeout")
	}
}

func (h *HealthMonitor) checkBridge(b *BridgeInfo) {
	ctx, cancel := context.WithTimeout(context.Background(), h.timeout)
	defer cancel()

	start := time.Now()
	isAlive := false
	latency := 0

	dialer := &net.Dialer{Timeout: h.timeout}
	conn, err := (&tls.Dialer{NetDialer: dialer, Config: &tls.Config{
		InsecureSkipVerify: true,
	}}).DialContext(ctx, "tcp", b.Address)

	if err != nil {
		var d net.Dialer
		tcpConn, tcpErr := d.DialContext(ctx, "tcp", b.Address)
		if tcpErr == nil {
			isAlive = true
			latency = int(time.Since(start).Milliseconds())
			tcpConn.Close()
		}
	} else {
		isAlive = true
		latency = int(time.Since(start).Milliseconds())
		conn.Close()
	}

	h.registry.UpdateBridgeStatus(b.ID, isAlive, latency)

	if isAlive {
		log.Printf("[BridgePool] Bridge %s (%s): alive, latency=%dms", b.ID, b.Address, latency)
	} else {
		log.Printf("[BridgePool] Bridge %s (%s): DEAD", b.ID, b.Address)
	}
}

func (h *HealthMonitor) CheckSingle(bridgeID string) (bool, int, error) {
	bridge, err := h.registry.GetBridge(bridgeID)
	if err != nil {
		return false, 0, err
	}

	h.checkBridge(bridge)
	return bridge.IsAlive, bridge.Latency, nil
}

type AdaptiveManager struct {
	registry      *Registry
	healthMonitor *HealthMonitor

	minBridges        int           
	maxLatency        int           
	failoverDelay     time.Duration 
	rebalanceInterval time.Duration
	currentBridge  string
	failedAttempts map[string]int
	ipCache        map[string]string

	onBridgeChange func(oldBridge, newBridge string)
	onIPChange     func(bridgeID, oldIP, newIP string)
	onScaleUp      func(reason string)
	onScaleDown    func(bridgeID string)

	stop chan struct{}
	mu   sync.RWMutex
}

func NewAdaptiveManager(registry *Registry) *AdaptiveManager {
	return &AdaptiveManager{
		registry:          registry,
		healthMonitor:     registry.healthMonitor,
		minBridges:        2,
		maxLatency:        500, // 500ms
		failoverDelay:     5 * time.Second,
		rebalanceInterval: 60 * time.Second,
		failedAttempts:    make(map[string]int),
		ipCache:           make(map[string]string),
		stop:              make(chan struct{}),
	}
}

func (am *AdaptiveManager) Start() {
	go am.adaptiveLoop()
	go am.rebalanceLoop()
	log.Println("[Adaptive] Bridge adaptation system started")
}

func (am *AdaptiveManager) Stop() {
	close(am.stop)
}
func (am *AdaptiveManager) SetMinBridges(n int) {
	am.mu.Lock()
	am.minBridges = n
	am.mu.Unlock()
}

func (am *AdaptiveManager) SetMaxLatency(ms int) {
	am.mu.Lock()
	am.maxLatency = ms
	am.mu.Unlock()
}

func (am *AdaptiveManager) OnBridgeChange(fn func(oldBridge, newBridge string)) {
	am.onBridgeChange = fn
}

func (am *AdaptiveManager) OnIPChange(fn func(bridgeID, oldIP, newIP string)) {
	am.onIPChange = fn
}
func (am *AdaptiveManager) OnScaleUp(fn func(reason string)) {
	am.onScaleUp = fn
}

func (am *AdaptiveManager) OnScaleDown(fn func(bridgeID string)) {
	am.onScaleDown = fn
}
func (am *AdaptiveManager) adaptiveLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			am.checkAndAdapt()
		case <-am.stop:
			return
		}
	}
}

func (am *AdaptiveManager) checkAndAdapt() {
	bridges := am.registry.GetAllBridges()
	aliveBridges := am.registry.GetAliveBridges()
	am.mu.RLock()
	minBridges := am.minBridges
	maxLatency := am.maxLatency
	am.mu.RUnlock()

	if len(aliveBridges) < minBridges {
		log.Printf("[Adaptive] Need more bridges: have %d, need %d", len(aliveBridges), minBridges)
		if am.onScaleUp != nil {
			am.onScaleUp("insufficient_bridges")
		}
	}

	for _, b := range bridges {
		am.mu.Lock()
		oldIP, exists := am.ipCache[b.ID]
		if exists && oldIP != b.Address {
			log.Printf("[Adaptive] Bridge %s IP changed: %s → %s", b.ID, oldIP, b.Address)
			if am.onIPChange != nil {
				am.onIPChange(b.ID, oldIP, b.Address)
			}
		}
		am.ipCache[b.ID] = b.Address
		am.mu.Unlock()
	}

	am.mu.RLock()
	currentBridge := am.currentBridge
	am.mu.RUnlock()

	if currentBridge != "" {
		current, err := am.registry.GetBridge(currentBridge)
		if err != nil || !current.IsAlive || current.Latency > maxLatency {
			am.failover(currentBridge)
		}
	}

	for _, b := range bridges {
		am.mu.Lock()
		if !b.IsAlive {
			am.failedAttempts[b.ID]++
			if am.failedAttempts[b.ID] >= 5 {
				log.Printf("[Adaptive] Removing consistently failing bridge: %s", b.ID)
				if am.onScaleDown != nil {
					am.onScaleDown(b.ID)
				}
				delete(am.failedAttempts, b.ID)
			}
		} else {
			am.failedAttempts[b.ID] = 0
		}
		am.mu.Unlock()
	}
}

func (am *AdaptiveManager) failover(fromBridge string) {
	aliveBridges := am.registry.GetAliveBridges()
	if len(aliveBridges) == 0 {
		log.Println("[Adaptive] CRITICAL: No alive bridges for failover!")
		return
	}

	newBridge := aliveBridges[0]

	if newBridge.ID == fromBridge && len(aliveBridges) > 1 {
		newBridge = aliveBridges[1]
	}

	am.mu.Lock()
	oldBridge := am.currentBridge
	am.currentBridge = newBridge.ID
	am.mu.Unlock()

	log.Printf("[Adaptive] Failover: %s → %s (latency: %dms, trust: %d)",
		oldBridge, newBridge.ID, newBridge.Latency, newBridge.TrustLevel)

	if am.onBridgeChange != nil {
		am.onBridgeChange(oldBridge, newBridge.ID)
	}
}

func (am *AdaptiveManager) rebalanceLoop() {
	ticker := time.NewTicker(am.rebalanceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			am.rebalance()
		case <-am.stop:
			return
		}
	}
}

func (am *AdaptiveManager) rebalance() {
	am.mu.RLock()
	currentID := am.currentBridge
	am.mu.RUnlock()

	if currentID == "" {
		return
	}

	current, err := am.registry.GetBridge(currentID)
	if err != nil {
		return
	}

	aliveBridges := am.registry.GetAliveBridges()
	if len(aliveBridges) == 0 {
		return
	}

	best := aliveBridges[0]

	if best.ID != current.ID {
		latencyImprovement := float64(current.Latency-best.Latency) / float64(current.Latency)
		trustImprovement := best.TrustLevel - current.TrustLevel

		if latencyImprovement > 0.2 || trustImprovement > 10 {
			log.Printf("[Adaptive] Rebalancing to better bridge: %s → %s", current.ID, best.ID)
			am.failover(current.ID)
		}
	}
}

func (am *AdaptiveManager) GetCurrentBridge() (*BridgeInfo, error) {
	am.mu.RLock()
	currentID := am.currentBridge
	am.mu.RUnlock()

	if currentID == "" {
		aliveBridges := am.registry.GetAliveBridges()
		if len(aliveBridges) == 0 {
			return nil, errors.New("no alive bridges")
		}
		am.mu.Lock()
		am.currentBridge = aliveBridges[0].ID
		currentID = am.currentBridge
		am.mu.Unlock()
	}

	return am.registry.GetBridge(currentID)
}

func (am *AdaptiveManager) ForceSwitch(bridgeID string) error {
	bridge, err := am.registry.GetBridge(bridgeID)
	if err != nil {
		return err
	}
	if !bridge.IsAlive {
		return errors.New("bridge is not alive")
	}

	am.mu.Lock()
	oldBridge := am.currentBridge
	am.currentBridge = bridgeID
	am.mu.Unlock()

	log.Printf("[Adaptive] Forced switch: %s → %s", oldBridge, bridgeID)
	if am.onBridgeChange != nil {
		am.onBridgeChange(oldBridge, bridgeID)
	}
	return nil
}

type TransportMode string

const (
	TransportDirect      TransportMode = "direct"
	TransportVKLongpoll  TransportMode = "vk_longpoll"
	TransportVKStreaming TransportMode = "vk_streaming"
	TransportVKWebRTC    TransportMode = "vk_webrtc"
	TransportCDN         TransportMode = "cdn"
)

type TransportAdaptiveManager struct {
	*AdaptiveManager

	currentMode TransportMode

	modePriority []TransportMode

	modeStats map[TransportMode]*ModeStats

	consecutiveFailures int
	blockingThreshold   int

	onModeChange func(oldMode, newMode TransportMode, reason string)

	vkToken   string
	vkGroupID int64
	vkPeerID  int64

	modeMu sync.RWMutex
}

type ModeStats struct {
	Attempts     int
	Successes    int
	Failures     int
	LastAttempt  time.Time
	LastSuccess  time.Time
	AvgLatency   int
	BlockedUntil time.Time
}

func NewTransportAdaptiveManager(registry *Registry) *TransportAdaptiveManager {
	return &TransportAdaptiveManager{
		AdaptiveManager: NewAdaptiveManager(registry),
		currentMode:     TransportDirect,
		modePriority: []TransportMode{
			TransportDirect,
			TransportCDN,
			TransportVKStreaming,
			TransportVKWebRTC,
			TransportVKLongpoll,
		},
		modeStats:         make(map[TransportMode]*ModeStats),
		blockingThreshold: 3,
	}
}

func (tam *TransportAdaptiveManager) SetVKConfig(token string, groupID, peerID int64) {
	tam.modeMu.Lock()
	tam.vkToken = token
	tam.vkGroupID = groupID
	tam.vkPeerID = peerID
	tam.modeMu.Unlock()
}

func (tam *TransportAdaptiveManager) OnModeChange(fn func(oldMode, newMode TransportMode, reason string)) {
	tam.onModeChange = fn
}
func (tam *TransportAdaptiveManager) SetModePriority(modes []TransportMode) {
	tam.modeMu.Lock()
	tam.modePriority = modes
	tam.modeMu.Unlock()
}

func (tam *TransportAdaptiveManager) GetCurrentMode() TransportMode {
	tam.modeMu.RLock()
	defer tam.modeMu.RUnlock()
	return tam.currentMode
}

func (tam *TransportAdaptiveManager) RecordSuccess(mode TransportMode, latency int) {
	tam.modeMu.Lock()
	defer tam.modeMu.Unlock()

	if tam.modeStats[mode] == nil {
		tam.modeStats[mode] = &ModeStats{}
	}

	stats := tam.modeStats[mode]
	stats.Attempts++
	stats.Successes++
	stats.LastAttempt = time.Now()
	stats.LastSuccess = time.Now()

	if stats.AvgLatency == 0 {
		stats.AvgLatency = latency
	} else {
		stats.AvgLatency = (stats.AvgLatency*7 + latency*3) / 10
	}

	if mode == tam.currentMode {
		tam.consecutiveFailures = 0
	}

	log.Printf("[Transport] Mode %s: success (latency: %dms, avg: %dms)", mode, latency, stats.AvgLatency)
}

func (tam *TransportAdaptiveManager) RecordFailure(mode TransportMode, reason string) {
	tam.modeMu.Lock()
	defer tam.modeMu.Unlock()

	if tam.modeStats[mode] == nil {
		tam.modeStats[mode] = &ModeStats{}
	}

	stats := tam.modeStats[mode]
	stats.Attempts++
	stats.Failures++
	stats.LastAttempt = time.Now()

	if mode == tam.currentMode {
		tam.consecutiveFailures++
		log.Printf("[Transport] Mode %s: failure #%d (%s)", mode, tam.consecutiveFailures, reason)

		if tam.consecutiveFailures >= tam.blockingThreshold {
			tam.switchToNextMode("blocking_detected")
		}
	}
}

func (tam *TransportAdaptiveManager) switchToNextMode(reason string) {
	currentIdx := -1
	for i, m := range tam.modePriority {
		if m == tam.currentMode {
			currentIdx = i
			break
		}
	}

	for i := currentIdx + 1; i < len(tam.modePriority); i++ {
		nextMode := tam.modePriority[i]

		if stats, ok := tam.modeStats[nextMode]; ok {
			if time.Now().Before(stats.BlockedUntil) {
				continue
			}
		}

		if tam.isVKMode(nextMode) && tam.vkToken == "" {
			continue
		}
		oldMode := tam.currentMode
		tam.currentMode = nextMode
		tam.consecutiveFailures = 0
		if tam.modeStats[oldMode] == nil {
			tam.modeStats[oldMode] = &ModeStats{}
		}
		tam.modeStats[oldMode].BlockedUntil = time.Now().Add(5 * time.Minute)

		log.Printf("[Transport] Switching mode: %s → %s (reason: %s)", oldMode, nextMode, reason)

		if tam.onModeChange != nil {
			tam.onModeChange(oldMode, nextMode, reason)
		}
		return
	}

	for _, m := range tam.modePriority {
		if stats, ok := tam.modeStats[m]; ok {
			if time.Now().Before(stats.BlockedUntil) {
				continue
			}
		}
		if tam.isVKMode(m) && tam.vkToken == "" {
			continue
		}

		oldMode := tam.currentMode
		tam.currentMode = m
		tam.consecutiveFailures = 0
		log.Printf("[Transport] Cycling back to mode: %s", m)

		if tam.onModeChange != nil {
			tam.onModeChange(oldMode, m, "cycle_back")
		}
		return
	}

	log.Println("[Transport] WARNING: No available transport modes!")
}

func (tam *TransportAdaptiveManager) isVKMode(mode TransportMode) bool {
	return mode == TransportVKLongpoll || mode == TransportVKStreaming || mode == TransportVKWebRTC
}

func (tam *TransportAdaptiveManager) ForceMode(mode TransportMode) error {
	tam.modeMu.Lock()
	defer tam.modeMu.Unlock()

	if tam.isVKMode(mode) && tam.vkToken == "" {
		return errors.New("VK token not configured")
	}

	oldMode := tam.currentMode
	tam.currentMode = mode
	tam.consecutiveFailures = 0

	log.Printf("[Transport] Forced mode switch: %s → %s", oldMode, mode)

	if tam.onModeChange != nil {
		tam.onModeChange(oldMode, mode, "forced")
	}
	return nil
}

func (tam *TransportAdaptiveManager) GetModeStats(mode TransportMode) *ModeStats {
	tam.modeMu.RLock()
	defer tam.modeMu.RUnlock()
	return tam.modeStats[mode]
}

func (tam *TransportAdaptiveManager) GetAllModeStats() map[TransportMode]*ModeStats {
	tam.modeMu.RLock()
	defer tam.modeMu.RUnlock()

	result := make(map[TransportMode]*ModeStats)
	for k, v := range tam.modeStats {
		result[k] = v
	}
	return result
}

func (tam *TransportAdaptiveManager) TryDirectThenFallback(connectFn func(TransportMode) error) error {
	mode := tam.GetCurrentMode()

	err := connectFn(mode)
	if err == nil {
		tam.RecordSuccess(mode, 0)
		return nil
	}

	tam.RecordFailure(mode, err.Error())

	newMode := tam.GetCurrentMode()
	if newMode != mode {
		return connectFn(newMode)
	}

	return err
}

type BridgeTransportConfig struct {
	Mode        TransportMode   `json:"mode"`
	VKToken     string          `json:"vk_token,omitempty"`
	VKGroupID   int64           `json:"vk_group_id,omitempty"`
	VKPeerID    int64           `json:"vk_peer_id,omitempty"`
	StreamKey   string          `json:"stream_key,omitempty"`
	FallbackSeq []TransportMode `json:"fallback_sequence,omitempty"`
}

func (tam *TransportAdaptiveManager) GetBridgeTransportConfig() BridgeTransportConfig {
	tam.modeMu.RLock()
	defer tam.modeMu.RUnlock()

	return BridgeTransportConfig{
		Mode:        tam.currentMode,
		VKToken:     tam.vkToken,
		VKGroupID:   tam.vkGroupID,
		VKPeerID:    tam.vkPeerID,
		FallbackSeq: tam.modePriority,
	}
}
