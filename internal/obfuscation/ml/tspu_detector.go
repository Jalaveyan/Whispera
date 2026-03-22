package ml

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// ТСПУ (Технические средства противодействия угрозам) — Russia's national DPI system
// deployed at ISP level by Roskomnadzor. This detector identifies TSPU-specific
// blocking patterns that differ from generic DPI.
//
// TSPU blocking signatures:
// 1. RST injection — TCP RST sent after ClientHello with blocked SNI (within 1-5ms)
// 2. Throttling — bandwidth reduction to ~128kbps for specific protocols
// 3. Replay attack — TSPU replays recorded TLS handshakes to detect proxies
// 4. SNI-based blocking — immediate connection drop based on SNI field
// 5. Protocol fingerprinting — blocking non-standard TLS fingerprints (JA3)
// 6. Active probing — TSPU connects to suspected proxy servers

const (
	// DPI type IDs for TSPU-specific detections.
	DPITypeNone              = 0
	DPITypeHTTPInspection    = 1
	DPITypeTLSInspection     = 2
	DPITypeDeepPacket        = 3
	DPITypeProtocolFP        = 4
	DPITypeOKRuFP            = 5
	DPITypeTSPURST           = 6 // RST injection after ClientHello
	DPITypeTSPUThrottle      = 7 // bandwidth throttling
	DPITypeTSPUReplay        = 8 // TLS handshake replay/active probe

	TSPUHistoryWindow       = 100 // connection events to keep
	TSPURSTThresholdMs      = 10  // RST within this time = suspicious
	TSPUThrottleBWKbps      = 200 // bandwidth below this = throttling
	TSPUReplayWindowSec     = 60  // replay detection window
)

// TSPUDetector tracks connection-level events to identify TSPU blocking patterns.
type TSPUDetector struct {
	mu sync.Mutex

	// RST injection tracking.
	rstEvents     []rstEvent
	rstIdx        int
	rstFull       bool

	// Throttle detection.
	bwSamples     []bwSample
	bwIdx         int
	bwFull        bool

	// TLS replay detection (TSPU sends back recorded ClientHellos).
	seenHellos    map[uint64]time.Time // hash → first seen
	helloCleanup  time.Time

	// Counters.
	rstDetections      int64
	throttleDetections int64
	replayDetections   int64
	totalChecks        int64
}

type rstEvent struct {
	SNI       string
	TimeToRST time.Duration // time from SYN-ACK to RST
	Timestamp time.Time
	Blocked   bool
}

type bwSample struct {
	Transport string
	BytesPerSec float64
	Timestamp   time.Time
}

// NewTSPUDetector creates a new TSPU-aware DPI detector.
func NewTSPUDetector() *TSPUDetector {
	return &TSPUDetector{
		rstEvents:  make([]rstEvent, TSPUHistoryWindow),
		bwSamples:  make([]bwSample, TSPUHistoryWindow),
		seenHellos: make(map[uint64]time.Time),
	}
}

// RecordRST records a TCP RST event for TSPU RST injection detection.
// timeToRST is the time between connection establishment and RST receipt.
func (d *TSPUDetector) RecordRST(sni string, timeToRST time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()

	blocked := timeToRST < time.Duration(TSPURSTThresholdMs)*time.Millisecond
	d.rstEvents[d.rstIdx] = rstEvent{
		SNI:       sni,
		TimeToRST: timeToRST,
		Timestamp: time.Now(),
		Blocked:   blocked,
	}
	d.rstIdx = (d.rstIdx + 1) % TSPUHistoryWindow
	if d.rstIdx == 0 {
		d.rstFull = true
	}

	if blocked {
		atomic.AddInt64(&d.rstDetections, 1)
	}
	atomic.AddInt64(&d.totalChecks, 1)
}

// RecordBandwidth records a bandwidth measurement for throttle detection.
func (d *TSPUDetector) RecordBandwidth(transport string, bytesPerSec float64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.bwSamples[d.bwIdx] = bwSample{
		Transport:   transport,
		BytesPerSec: bytesPerSec,
		Timestamp:   time.Now(),
	}
	d.bwIdx = (d.bwIdx + 1) % TSPUHistoryWindow
	if d.bwIdx == 0 {
		d.bwFull = true
	}

	if bytesPerSec < TSPUThrottleBWKbps*1024/8 {
		atomic.AddInt64(&d.throttleDetections, 1)
	}
}

// RecordClientHello records a TLS ClientHello hash for replay detection.
// If the same hash appears from a different source within the window, it's a TSPU replay probe.
func (d *TSPUDetector) RecordClientHello(helloHash uint64, fromServer bool) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Cleanup old entries periodically.
	now := time.Now()
	if now.Sub(d.helloCleanup) > time.Minute {
		cutoff := now.Add(-time.Duration(TSPUReplayWindowSec) * time.Second)
		for k, t := range d.seenHellos {
			if t.Before(cutoff) {
				delete(d.seenHellos, k)
			}
		}
		d.helloCleanup = now
	}

	if fromServer {
		// Server received a ClientHello — check if we've seen it before from our client.
		if _, exists := d.seenHellos[helloHash]; exists {
			// Same ClientHello replayed — TSPU active probe detected.
			atomic.AddInt64(&d.replayDetections, 1)
			return true
		}
	} else {
		// Client sent a ClientHello — record it.
		d.seenHellos[helloHash] = now
	}
	return false
}

// DetectTSPU analyzes recent events and returns the TSPU DPI type and confidence.
// Returns (dpiType, confidence) where dpiType is one of DPITypeTSPU*.
func (d *TSPUDetector) DetectTSPU() (dpiType int, confidence float64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	window := 5 * time.Minute

	// 1. Check for RST injection pattern.
	rstCount := 0
	rstTotal := 0
	size := d.rstIdx
	if d.rstFull {
		size = TSPUHistoryWindow
	}
	for i := 0; i < size; i++ {
		ev := d.rstEvents[i]
		if now.Sub(ev.Timestamp) > window {
			continue
		}
		rstTotal++
		if ev.Blocked {
			rstCount++
		}
	}
	if rstTotal >= 3 && float64(rstCount)/float64(rstTotal) > 0.5 {
		conf := math.Min(float64(rstCount)/float64(rstTotal), 0.95)
		return DPITypeTSPURST, conf
	}

	// 2. Check for throttling pattern.
	throttled := 0
	bwTotal := 0
	bwSize := d.bwIdx
	if d.bwFull {
		bwSize = TSPUHistoryWindow
	}
	for i := 0; i < bwSize; i++ {
		s := d.bwSamples[i]
		if now.Sub(s.Timestamp) > window {
			continue
		}
		bwTotal++
		if s.BytesPerSec < TSPUThrottleBWKbps*1024/8 {
			throttled++
		}
	}
	if bwTotal >= 5 && float64(throttled)/float64(bwTotal) > 0.6 {
		conf := math.Min(float64(throttled)/float64(bwTotal), 0.90)
		return DPITypeTSPUThrottle, conf
	}

	// 3. Check for replay/active probe.
	replayCount := atomic.LoadInt64(&d.replayDetections)
	if replayCount > 0 {
		conf := math.Min(0.7+float64(replayCount)*0.05, 0.95)
		return DPITypeTSPUReplay, conf
	}

	return DPITypeNone, 0
}

// GetTSPUFeatures returns TSPU-specific features for the ML model (appended to standard features).
func (d *TSPUDetector) GetTSPUFeatures() []float64 {
	d.mu.Lock()
	defer d.mu.Unlock()

	features := make([]float64, 6)
	now := time.Now()
	window := 5 * time.Minute

	// Feature 0: RST injection rate (0-1).
	rstCount, rstTotal := 0, 0
	size := d.rstIdx
	if d.rstFull {
		size = TSPUHistoryWindow
	}
	for i := 0; i < size; i++ {
		if now.Sub(d.rstEvents[i].Timestamp) <= window {
			rstTotal++
			if d.rstEvents[i].Blocked {
				rstCount++
			}
		}
	}
	if rstTotal > 0 {
		features[0] = float64(rstCount) / float64(rstTotal)
	}

	// Feature 1: Average time-to-RST (normalized, lower = more suspicious).
	if rstCount > 0 {
		var avgRST float64
		for i := 0; i < size; i++ {
			if d.rstEvents[i].Blocked && now.Sub(d.rstEvents[i].Timestamp) <= window {
				avgRST += float64(d.rstEvents[i].TimeToRST.Milliseconds())
			}
		}
		avgRST /= float64(rstCount)
		features[1] = 1.0 - math.Min(avgRST/100.0, 1.0) // 0ms→1.0, 100ms→0.0
	}

	// Feature 2: Throttle rate (0-1).
	throttled, bwTotal := 0, 0
	bwSize := d.bwIdx
	if d.bwFull {
		bwSize = TSPUHistoryWindow
	}
	for i := 0; i < bwSize; i++ {
		if now.Sub(d.bwSamples[i].Timestamp) <= window {
			bwTotal++
			if d.bwSamples[i].BytesPerSec < TSPUThrottleBWKbps*1024/8 {
				throttled++
			}
		}
	}
	if bwTotal > 0 {
		features[2] = float64(throttled) / float64(bwTotal)
	}

	// Feature 3: Average bandwidth (normalized).
	if bwTotal > 0 {
		var avgBW float64
		for i := 0; i < bwSize; i++ {
			if now.Sub(d.bwSamples[i].Timestamp) <= window {
				avgBW += d.bwSamples[i].BytesPerSec
			}
		}
		avgBW /= float64(bwTotal)
		features[3] = math.Min(avgBW/(10*1024*1024), 1.0) // normalize to 10MB/s
	}

	// Feature 4: Replay detections (saturating counter).
	features[4] = math.Min(float64(atomic.LoadInt64(&d.replayDetections))/10.0, 1.0)

	// Feature 5: Overall TSPU suspicion score.
	features[5] = math.Min(features[0]*0.4+features[2]*0.3+features[4]*0.3, 1.0)

	return features
}

// Stats returns TSPU detection statistics.
func (d *TSPUDetector) Stats() map[string]interface{} {
	return map[string]interface{}{
		"rst_detections":      atomic.LoadInt64(&d.rstDetections),
		"throttle_detections": atomic.LoadInt64(&d.throttleDetections),
		"replay_detections":   atomic.LoadInt64(&d.replayDetections),
		"total_checks":        atomic.LoadInt64(&d.totalChecks),
	}
}

// TSPUCountermeasure returns the recommended evasion strategy for a detected TSPU type.
func TSPUCountermeasure(dpiType int) string {
	switch dpiType {
	case DPITypeTSPURST:
		// RST injection: use encrypted SNI (ECH) or domain fronting, or tunnel through CDN.
		return "cdn-ws"
	case DPITypeTSPUThrottle:
		// Throttling: switch to a protocol that TSPU doesn't throttle (e.g. vkvideo, reality).
		return "vkvideo"
	case DPITypeTSPUReplay:
		// Active probing: use protocols resistant to replay (reality, shadowtls).
		return "reality"
	default:
		return ""
	}
}

// dpiTypeName returns a human-readable name for a DPI type ID.
func dpiTypeName(dpiType int) string {
	switch dpiType {
	case DPITypeHTTPInspection:
		return "http_inspection"
	case DPITypeTLSInspection:
		return "tls_inspection"
	case DPITypeDeepPacket:
		return "deep_packet_inspection"
	case DPITypeProtocolFP:
		return "protocol_fingerprint"
	case DPITypeOKRuFP:
		return "ok_ru_fingerprint"
	case DPITypeTSPURST:
		return "tspu_rst_injection"
	case DPITypeTSPUThrottle:
		return "tspu_throttling"
	case DPITypeTSPUReplay:
		return "tspu_replay_probe"
	default:
		return ""
	}
}
