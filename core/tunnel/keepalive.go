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

// recentActivityWindow guards against false-positive reconnects: a pooled
// connection that's busy carrying a backlog of bulk data shares the same
// FIFO write queue (bufferedPipeWriter, see core/protocol/h2conn.go) as the
// keepalive ping, so the ping can legitimately queue behind it and miss its
// deadline on a perfectly healthy, just-busy connection.
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

	if !m.lastPong.IsZero() && m.GetState() == StateConnected {
		silentDuration := time.Since(m.lastPong)
		maxSilence := 90 * time.Second
		if silentDuration > maxSilence && time.Since(m.LastActivity()) > recentActivityWindow {
			log.Warn("keepalive: reconnecting after %s without a pong", silentDuration)
			go m.Reconnect(m.Context())
			return
		}

		if !m.lastKeepalive.IsZero() && m.lastPong.Before(m.lastKeepalive) {
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
	go func() { done <- m.Send(pingFrame) }()

	select {
	case err := <-done:
		if err != nil {
			k.reconnectOnMissed(m, fmt.Sprintf("ping send failed: %v", err))
		} else {
			m.lastKeepalive = time.Now()
		}
	case <-time.After(sendTimeout):
		if time.Since(m.LastActivity()) >= recentActivityWindow {
			atomic.AddInt32(&m.missedKAs, 1)
		}
	}
}
