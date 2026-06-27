package tunnel

import (
	"context"
	"fmt"
	mrand "math/rand"
	"sync/atomic"
	"time"
	"whispera/neural"
)

type keepaliveController struct {
	m      *Manager
	cancel context.CancelFunc
}

func newKeepaliveController(m *Manager) *keepaliveController {
	return &keepaliveController{m: m}
}

func (k *keepaliveController) start() {
	k.stop()
	k.send()

	ctx, cancel := context.WithCancel(context.Background())
	k.cancel = cancel

	go func() {
		m := k.m
		for {
			rttMs := float64(atomic.LoadInt64(&m.qualityRTTEWMA)) / 1e6
			missed := int(atomic.LoadInt32(&m.missedKAs))
			kaView := neural.KeepaliveView{RTTMs: rttMs, MissedKAs: missed}

			base := m.config.KeepaliveInterval
			if m.ml.kaAgent != nil {
				base = m.ml.kaAgent.Decide(kaView)
			}

			jitterFrac := 0.30
			if m.ml.jitterAgent != nil {
				jitterFrac = m.ml.jitterAgent.Decide(neural.JitterView{
					RTTMs: rttMs, MissedKAs: missed,
				})
			}

			jitter := time.Duration(float64(base) * jitterFrac * (2*mrand.Float64() - 1))
			timer := time.NewTimer(base + jitter)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				k.send()
			}
		}
	}()
}

func (k *keepaliveController) stop() {
	if k.cancel != nil {
		k.cancel()
	}
}

const minMissedKeepalives = 3

const recentActivityWindow = 10 * time.Second

func (k *keepaliveController) missedThreshold(m *Manager) int {
	threshold := m.config.QualityMissedKeepalives
	if threshold <= 0 {
		threshold = minMissedKeepalives
	}
	return threshold
}

func (k *keepaliveController) reconnectOnMissed(m *Manager, reason string) {
	if time.Since(m.LastActivity()) < recentActivityWindow {
		atomic.StoreInt32(&m.missedKAs, 0)
		return
	}
	missed := atomic.AddInt32(&m.missedKAs, 1)
	if int(missed) < k.missedThreshold(m) {
		return
	}
	atomic.StoreInt32(&m.missedKAs, 0)
	if m.GetState() == StateConnected {
		log.Warn("keepalive: reconnecting after %d missed pings (%s)", missed, reason)
		go m.Reconnect(m.Context())
	}
}

func (k *keepaliveController) send() {
	m := k.m

	lastPong := atomic.LoadInt64(&m.lastPong)
	if lastPong != 0 && m.GetState() == StateConnected {
		silentDuration := time.Since(time.Unix(0, lastPong))
		maxSilence := time.Duration(k.missedThreshold(m)) * m.config.KeepaliveInterval
		if silentDuration > maxSilence && time.Since(m.LastActivity()) > recentActivityWindow {
			log.Warn("keepalive: reconnecting after %s without a pong", silentDuration)
			go m.Reconnect(m.Context())
			return
		}

		lastKeepalive := atomic.LoadInt64(&m.lastKeepalive)
		if lastKeepalive != 0 && lastPong < lastKeepalive {
			if time.Since(m.LastActivity()) < recentActivityWindow {
				return
			}
			if m.ml.kaAgent != nil {
				m.ml.kaAgent.RecordOutcome(0)
			}
			if m.ml.jitterAgent != nil {
				m.ml.jitterAgent.RecordOutcome(0)
			}
			k.reconnectOnMissed(m, "no pong since last ping")
			return
		}
	}

	pingFrame := make([]byte, 8)
	pingFrame[2] = 0x06

	sendTimeout := m.config.KeepaliveInterval
	if sendTimeout <= 0 {
		sendTimeout = 30 * time.Second
	}

	done := make(chan error, 1)
	go func() {
		err := m.Send(pingFrame)
		if err == nil {
			atomic.StoreInt64(&m.lastKeepalive, time.Now().UnixNano())
		}
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			k.reconnectOnMissed(m, fmt.Sprintf("ping send failed: %v", err))
		}
	case <-time.After(sendTimeout):
		if time.Since(m.LastActivity()) >= recentActivityWindow {
			atomic.AddInt32(&m.missedKAs, 1)
		}
	}
}

func (k *keepaliveController) probeNow(timeout time.Duration) bool {
	m := k.m
	pingFrame := make([]byte, 8)
	pingFrame[2] = 0x06
	if err := m.Send(pingFrame); err != nil {
		return false
	}
	sentAt := time.Now().UnixNano()
	atomic.StoreInt64(&m.lastKeepalive, sentAt)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&m.lastPong) >= sentAt {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
