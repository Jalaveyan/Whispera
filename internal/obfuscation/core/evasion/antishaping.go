package evasion

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

type MorphProfile int

const (
	MorphNone MorphProfile = iota
	MorphVideoStream
	MorphVoIP
	MorphWebBrowsing
	MorphFileDownload
	MorphMessenger
)

type ShapingState int

const (
	StateNormal ShapingState = iota
	StateThrottled
	StateShaped
	StateBlocked
)

type AntiShaping struct {
	mu sync.RWMutex

	enabled       bool
	activeProfile MorphProfile
	state         ShapingState

	detector  *shapingDetector
	morpher   *trafficMorpher
	splitter  *packetSplitter
	adapter   *rateAdapter

	stopCh   chan struct{}
	stopOnce sync.Once

	bytesOut     uint64
	bytesIn      uint64
	morphed      uint64
	splits       uint64
	merges       uint64
	adaptations  uint64
	detections   uint64
}

type AntiShapingConfig struct {
	Enabled          bool
	Profile          MorphProfile
	DetectInterval   time.Duration
	WindowSize       int
	ThrottleThresh   float64
	MinThroughput    int64
	MorphEnabled     bool
	SplitEnabled     bool
	AdaptEnabled     bool
	SplitMinSize     int
	SplitMaxSize     int
	MergeMaxDelay    time.Duration
	MergeMaxSize     int
}

func DefaultAntiShapingConfig() *AntiShapingConfig {
	return &AntiShapingConfig{
		Enabled:        true,
		Profile:        MorphVideoStream,
		DetectInterval: 2 * time.Second,
		WindowSize:     30,
		ThrottleThresh: 0.4,
		MinThroughput:  50000,
		MorphEnabled:   true,
		SplitEnabled:   true,
		AdaptEnabled:   true,
		SplitMinSize:   64,
		SplitMaxSize:   1200,
		MergeMaxDelay:  10 * time.Millisecond,
		MergeMaxSize:   1400,
	}
}

func NewAntiShaping(cfg *AntiShapingConfig) *AntiShaping {
	if cfg == nil {
		cfg = DefaultAntiShapingConfig()
	}

	as := &AntiShaping{
		enabled:       cfg.Enabled,
		activeProfile: cfg.Profile,
		state:         StateNormal,
		stopCh:        make(chan struct{}),
	}

	as.detector = newShapingDetector(cfg.DetectInterval, cfg.WindowSize, cfg.ThrottleThresh, cfg.MinThroughput)
	as.morpher = newTrafficMorpher(cfg.Profile)
	as.splitter = newPacketSplitter(cfg.SplitMinSize, cfg.SplitMaxSize, cfg.MergeMaxDelay, cfg.MergeMaxSize)
	as.adapter = newRateAdapter()

	if cfg.Enabled {
		go as.detectionLoop()
	}

	return as
}

func (as *AntiShaping) ProcessOutbound(data []byte, send func([]byte) error) error {
	if !as.enabled {
		return send(data)
	}

	atomic.AddUint64(&as.bytesOut, uint64(len(data)))
	as.detector.recordSend(len(data))

	as.mu.RLock()
	state := as.state
	profile := as.activeProfile
	as.mu.RUnlock()

	if state == StateNormal {
		shaped := as.morpher.shape(data, profile)
		if len(shaped) != len(data) {
			atomic.AddUint64(&as.morphed, 1)
		}
		return send(shaped)
	}

	morphed := as.morpher.shape(data, profile)
	atomic.AddUint64(&as.morphed, 1)

	chunks := as.splitter.split(morphed)
	if len(chunks) > 1 {
		atomic.AddUint64(&as.splits, uint64(len(chunks)))
	}

	delays := as.adapter.pacing(len(chunks), state)

	for i, chunk := range chunks {
		if i < len(delays) && delays[i] > 0 {
			time.Sleep(delays[i])
		}
		framed := frameChunk(chunk, i == len(chunks)-1, len(chunks))
		if err := send(framed); err != nil {
			return err
		}
	}

	return nil
}

func (as *AntiShaping) ProcessInbound(data []byte) []byte {
	if !as.enabled {
		return data
	}

	atomic.AddUint64(&as.bytesIn, uint64(len(data)))
	as.detector.recordRecv(len(data))

	if len(data) < 5 {
		return data
	}

	return unframeChunk(data)
}

func (as *AntiShaping) MergeInbound(fragments [][]byte) []byte {
	atomic.AddUint64(&as.merges, 1)
	return as.splitter.merge(fragments)
}

func (as *AntiShaping) SetProfile(p MorphProfile) {
	as.mu.Lock()
	as.activeProfile = p
	as.morpher.setProfile(p)
	as.mu.Unlock()
}

func (as *AntiShaping) GetState() ShapingState {
	as.mu.RLock()
	defer as.mu.RUnlock()
	return as.state
}

func (as *AntiShaping) Stats() map[string]interface{} {
	as.mu.RLock()
	state := as.state
	profile := as.activeProfile
	as.mu.RUnlock()

	return map[string]interface{}{
		"state":       state,
		"profile":     profile,
		"bytes_out":   atomic.LoadUint64(&as.bytesOut),
		"bytes_in":    atomic.LoadUint64(&as.bytesIn),
		"morphed":     atomic.LoadUint64(&as.morphed),
		"splits":      atomic.LoadUint64(&as.splits),
		"merges":      atomic.LoadUint64(&as.merges),
		"adaptations": atomic.LoadUint64(&as.adaptations),
		"detections":  atomic.LoadUint64(&as.detections),
		"throughput":  as.detector.currentThroughput(),
	}
}

func (as *AntiShaping) detectionLoop() {
	ticker := time.NewTicker(as.detector.interval)
	defer ticker.Stop()

	for {
		select {
		case <-as.stopCh:
			return
		case <-ticker.C:
			newState := as.detector.analyze()
			as.mu.Lock()
			oldState := as.state
			if newState != oldState {
				as.state = newState
				atomic.AddUint64(&as.detections, 1)
				as.onStateChange(oldState, newState)
			}
			as.mu.Unlock()
		}
	}
}

func (as *AntiShaping) onStateChange(from, to ShapingState) {
	atomic.AddUint64(&as.adaptations, 1)

	switch to {
	case StateThrottled:
		as.morpher.setProfile(MorphVideoStream)
		as.adapter.setMode(adaptAggressive)
	case StateShaped:
		as.morpher.setProfile(MorphVoIP)
		as.adapter.setMode(adaptEvasive)
	case StateBlocked:
		as.morpher.setProfile(MorphWebBrowsing)
		as.adapter.setMode(adaptSurvival)
	case StateNormal:
		as.morpher.setProfile(as.activeProfile)
		as.adapter.setMode(adaptNormal)
	}
}

func (as *AntiShaping) Stop() {
	as.stopOnce.Do(func() { close(as.stopCh) })
}

type shapingDetector struct {
	mu       sync.Mutex
	interval time.Duration

	sendSamples []throughputSample
	recvSamples []throughputSample
	windowSize  int

	throttleThresh float64
	minThroughput  int64

	currentSendBytes int64
	currentRecvBytes int64
	lastSampleTime   time.Time
}

type throughputSample struct {
	timestamp  time.Time
	bytes      int64
	throughput float64
}

func newShapingDetector(interval time.Duration, windowSize int, thresh float64, minTP int64) *shapingDetector {
	return &shapingDetector{
		interval:       interval,
		windowSize:     windowSize,
		throttleThresh: thresh,
		minThroughput:  minTP,
		lastSampleTime: time.Now(),
	}
}

func (sd *shapingDetector) recordSend(n int) {
	atomic.AddInt64(&sd.currentSendBytes, int64(n))
}

func (sd *shapingDetector) recordRecv(n int) {
	atomic.AddInt64(&sd.currentRecvBytes, int64(n))
}

func (sd *shapingDetector) currentThroughput() float64 {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	if len(sd.sendSamples) == 0 {
		return 0
	}
	return sd.sendSamples[len(sd.sendSamples)-1].throughput
}

func (sd *shapingDetector) analyze() ShapingState {
	sd.mu.Lock()
	defer sd.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(sd.lastSampleTime).Seconds()
	if elapsed < 0.01 {
		elapsed = 0.01
	}

	sendBytes := atomic.SwapInt64(&sd.currentSendBytes, 0)
	recvBytes := atomic.SwapInt64(&sd.currentRecvBytes, 0)
	sd.lastSampleTime = now

	sendTP := float64(sendBytes) / elapsed
	recvTP := float64(recvBytes) / elapsed

	sd.sendSamples = append(sd.sendSamples, throughputSample{now, sendBytes, sendTP})
	sd.recvSamples = append(sd.recvSamples, throughputSample{now, recvBytes, recvTP})

	if len(sd.sendSamples) > sd.windowSize {
		sd.sendSamples = sd.sendSamples[len(sd.sendSamples)-sd.windowSize:]
	}
	if len(sd.recvSamples) > sd.windowSize {
		sd.recvSamples = sd.recvSamples[len(sd.recvSamples)-sd.windowSize:]
	}

	if len(sd.sendSamples) < 5 {
		return StateNormal
	}

	avgSend := sd.movingAverage(sd.sendSamples)
	recentSend := sd.recentAverage(sd.sendSamples, 3)
	avgRecv := sd.movingAverage(sd.recvSamples)
	recentRecv := sd.recentAverage(sd.recvSamples, 3)

	if avgSend > 0 && recentRecv < float64(sd.minThroughput)*0.1 && recentSend > float64(sd.minThroughput) {
		return StateBlocked
	}

	if avgSend > 0 {
		sendDrop := 1.0 - (recentSend / avgSend)
		recvDrop := 0.0
		if avgRecv > 0 {
			recvDrop = 1.0 - (recentRecv / avgRecv)
		}

		if sendDrop > sd.throttleThresh*1.5 || recvDrop > sd.throttleThresh*1.5 {
			return StateShaped
		}

		if sendDrop > sd.throttleThresh || recvDrop > sd.throttleThresh {
			return StateThrottled
		}
	}

	variance := sd.throughputVariance(sd.sendSamples)
	if avgSend > 0 {
		cv := math.Sqrt(variance) / avgSend
		if cv > 1.5 {
			return StateThrottled
		}
	}

	return StateNormal
}

func (sd *shapingDetector) movingAverage(samples []throughputSample) float64 {
	if len(samples) == 0 {
		return 0
	}
	var sum float64
	for _, s := range samples {
		sum += s.throughput
	}
	return sum / float64(len(samples))
}

func (sd *shapingDetector) recentAverage(samples []throughputSample, n int) float64 {
	if len(samples) == 0 {
		return 0
	}
	start := len(samples) - n
	if start < 0 {
		start = 0
	}
	var sum float64
	count := 0
	for _, s := range samples[start:] {
		sum += s.throughput
		count++
	}
	if count == 0 {
		return 0
	}
	return sum / float64(count)
}

func (sd *shapingDetector) throughputVariance(samples []throughputSample) float64 {
	avg := sd.movingAverage(samples)
	if len(samples) < 2 {
		return 0
	}
	var sumSq float64
	for _, s := range samples {
		diff := s.throughput - avg
		sumSq += diff * diff
	}
	return sumSq / float64(len(samples)-1)
}

type trafficMorpher struct {
	mu      sync.RWMutex
	profile MorphProfile
	seq     uint32
}

func newTrafficMorpher(profile MorphProfile) *trafficMorpher {
	return &trafficMorpher{profile: profile}
}

func (tm *trafficMorpher) setProfile(p MorphProfile) {
	tm.mu.Lock()
	tm.profile = p
	tm.mu.Unlock()
}

func (tm *trafficMorpher) shape(data []byte, profile MorphProfile) []byte {
	tm.mu.Lock()
	seq := tm.seq
	tm.seq++
	tm.mu.Unlock()

	switch profile {
	case MorphVideoStream:
		return tm.morphToVideo(data, seq)
	case MorphVoIP:
		return tm.morphToVoIP(data)
	case MorphWebBrowsing:
		return tm.morphToWeb(data, seq)
	case MorphFileDownload:
		return tm.morphToDownload(data)
	case MorphMessenger:
		return tm.morphToMessenger(data)
	default:
		return data
	}
}

func (tm *trafficMorpher) morphToVideo(data []byte, seq uint32) []byte {
	frameSizes := []int{800, 1100, 1300, 1400, 200, 300, 150}
	targetSize := frameSizes[int(seq)%len(frameSizes)]
	targetSize += cryptoRandSmall(200) - 100

	result := make([]byte, 0, targetSize+16)

	result = append(result, 0x80|0x60)
	result = append(result, 0x60)

	seqBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(seqBytes, uint16(seq))
	result = append(result, seqBytes...)

	tsBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(tsBytes, seq*3000)
	result = append(result, tsBytes...)

	ssrc := make([]byte, 4)
	crand.Read(ssrc)
	result = append(result, ssrc...)

	result = append(result, 0x10)

	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(len(data)))
	result = append(result, lenBytes...)

	result = append(result, data...)

	if len(result) < targetSize {
		padding := make([]byte, targetSize-len(result))
		crand.Read(padding)
		result = append(result, padding...)
	}

	return result
}

func (tm *trafficMorpher) morphToVoIP(data []byte) []byte {
	packetSizes := []int{160, 320, 80, 240}
	targetSize := packetSizes[cryptoRandSmall(len(packetSizes))]

	result := make([]byte, 0, targetSize+8)

	result = append(result, 0x80)
	result = append(result, 0x08)

	seq := make([]byte, 2)
	crand.Read(seq)
	result = append(result, seq...)

	ts := make([]byte, 4)
	crand.Read(ts)
	result = append(result, ts...)

	ssrc := make([]byte, 4)
	crand.Read(ssrc)
	result = append(result, ssrc...)

	lenByte := make([]byte, 2)
	binary.BigEndian.PutUint16(lenByte, uint16(len(data)))
	result = append(result, lenByte...)

	result = append(result, data...)

	if len(result) < targetSize {
		padding := make([]byte, targetSize-len(result))
		crand.Read(padding)
		result = append(result, padding...)
	}

	return result
}

func (tm *trafficMorpher) morphToWeb(data []byte, seq uint32) []byte {
	if seq%5 == 0 {
		result := make([]byte, 0, len(data)+64)
		headers := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n")
		cl := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(data))
		result = append(result, headers...)
		result = append(result, []byte(cl)...)
		result = append(result, data...)
		return result
	}

	result := make([]byte, 0, len(data)+32)
	result = append(result, 0x17, 0x03, 0x03)
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(len(data)+16))
	result = append(result, lenBytes...)

	iv := make([]byte, 16)
	crand.Read(iv)
	result = append(result, iv...)
	result = append(result, data...)

	return result
}

func (tm *trafficMorpher) morphToDownload(data []byte) []byte {
	chunkSize := 16384
	if len(data) < chunkSize {
		chunkSize = len(data)
	}

	result := make([]byte, 0, chunkSize+32)
	result = append(result, 0x17, 0x03, 0x03)
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(chunkSize))
	result = append(result, lenBytes...)
	result = append(result, data[:chunkSize]...)

	if len(result) < 1400 {
		padding := make([]byte, 1400-len(result))
		crand.Read(padding)
		result = append(result, padding...)
	}

	return result
}

func (tm *trafficMorpher) morphToMessenger(data []byte) []byte {
	sizes := []int{64, 128, 192, 256, 384}
	target := sizes[cryptoRandSmall(len(sizes))]
	if target < len(data)+6 {
		target = len(data) + 6
	}

	result := make([]byte, 0, target)

	result = append(result, 0x82)

	if len(data) < 126 {
		result = append(result, byte(len(data)))
	} else {
		result = append(result, 126)
		lenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBytes, uint16(len(data)))
		result = append(result, lenBytes...)
	}

	mask := make([]byte, 4)
	crand.Read(mask)
	result = append(result, mask...)

	masked := make([]byte, len(data))
	for i := range data {
		masked[i] = data[i] ^ mask[i%4]
	}
	result = append(result, masked...)

	if len(result) < target {
		padding := make([]byte, target-len(result))
		crand.Read(padding)
		result = append(result, padding...)
	}

	return result
}

type packetSplitter struct {
	minSize       int
	maxSize       int
	mergeMaxDelay time.Duration
	mergeMaxSize  int
}

func newPacketSplitter(minSize, maxSize int, mergeDelay time.Duration, mergeMax int) *packetSplitter {
	if minSize < 32 {
		minSize = 32
	}
	if maxSize < minSize {
		maxSize = minSize * 2
	}
	if mergeMax < 256 {
		mergeMax = 256
	}
	return &packetSplitter{
		minSize:       minSize,
		maxSize:       maxSize,
		mergeMaxDelay: mergeDelay,
		mergeMaxSize:  mergeMax,
	}
}

func (ps *packetSplitter) split(data []byte) [][]byte {
	if len(data) <= ps.maxSize {
		return [][]byte{data}
	}

	var chunks [][]byte
	remaining := data
	for len(remaining) > 0 {
		chunkSize := ps.minSize + cryptoRandSmall(ps.maxSize-ps.minSize)
		if chunkSize > len(remaining) {
			chunkSize = len(remaining)
		}
		if len(remaining)-chunkSize < ps.minSize && len(remaining) <= ps.maxSize {
			chunkSize = len(remaining)
		}

		chunk := make([]byte, chunkSize)
		copy(chunk, remaining[:chunkSize])
		chunks = append(chunks, chunk)
		remaining = remaining[chunkSize:]
	}

	return chunks
}

func (ps *packetSplitter) merge(fragments [][]byte) []byte {
	totalSize := 0
	for _, f := range fragments {
		totalSize += len(f)
	}
	if totalSize == 0 {
		return nil
	}

	result := make([]byte, 0, totalSize)
	for _, f := range fragments {
		payload := unframeChunk(f)
		result = append(result, payload...)
	}
	return result
}

func frameChunk(data []byte, last bool, total int) []byte {
	flags := byte(0)
	if last {
		flags |= 0x01
	}

	result := make([]byte, 0, len(data)+5)
	result = append(result, 0xAA)
	result = append(result, flags)
	result = append(result, byte(total))

	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(len(data)))
	result = append(result, lenBytes...)

	result = append(result, data...)
	return result
}

func unframeChunk(data []byte) []byte {
	if len(data) < 5 || data[0] != 0xAA {
		return data
	}

	payloadLen := binary.BigEndian.Uint16(data[3:5])
	if int(payloadLen)+5 > len(data) {
		return data
	}
	return data[5 : 5+payloadLen]
}

type adaptMode int

const (
	adaptNormal adaptMode = iota
	adaptAggressive
	adaptEvasive
	adaptSurvival
)

type rateAdapter struct {
	mu   sync.RWMutex
	mode adaptMode
}

func newRateAdapter() *rateAdapter {
	return &rateAdapter{mode: adaptNormal}
}

func (ra *rateAdapter) setMode(m adaptMode) {
	ra.mu.Lock()
	ra.mode = m
	ra.mu.Unlock()
}

func (ra *rateAdapter) pacing(numChunks int, state ShapingState) []time.Duration {
	ra.mu.RLock()
	mode := ra.mode
	ra.mu.RUnlock()

	delays := make([]time.Duration, numChunks)
	if numChunks <= 1 {
		return delays
	}

	switch mode {
	case adaptNormal:
		for i := 1; i < numChunks; i++ {
			delays[i] = time.Duration(cryptoRandSmall(5)) * time.Millisecond
		}

	case adaptAggressive:
		for i := 1; i < numChunks; i++ {
			base := 10 + cryptoRandSmall(30)
			delays[i] = time.Duration(base) * time.Millisecond
		}

	case adaptEvasive:
		for i := 1; i < numChunks; i++ {
			base := 20 + cryptoRandSmall(80)
			if i%3 == 0 {
				base += cryptoRandSmall(50)
			}
			delays[i] = time.Duration(base) * time.Millisecond
		}

	case adaptSurvival:
		for i := 1; i < numChunks; i++ {
			base := 50 + cryptoRandSmall(200)
			delays[i] = time.Duration(base) * time.Millisecond
		}
	}

	for i := len(delays) - 1; i > 0; i-- {
		j := cryptoRandSmall(i + 1)
		delays[i], delays[j] = delays[j], delays[i]
	}

	return delays
}

func cryptoRandSmall(n int) int {
	if n <= 0 {
		return 0
	}
	b := make([]byte, 4)
	crand.Read(b)
	return int(binary.LittleEndian.Uint32(b)) % n
}
