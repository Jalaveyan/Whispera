package tunnel

import (
	"github.com/nekoskin/whispera/common/runtime/interfaces"
	"sync/atomic"
	"time"
)

func (m *Manager) updateQualityRTT(rtt time.Duration) {
	const alpha = 0.2
	old := atomic.LoadInt64(&m.qualityRTTEWMA)
	var newEWMA int64
	if old == 0 {
		newEWMA = int64(rtt)
	} else {
		newEWMA = int64(float64(old)*(1-alpha) + float64(rtt)*alpha)
	}
	atomic.StoreInt64(&m.qualityRTTEWMA, newEWMA)
}

func (m *Manager) GetQualityMetrics() (avgRTT time.Duration, missedKeepalives int) {
	return time.Duration(atomic.LoadInt64(&m.qualityRTTEWMA)),
		int(atomic.LoadInt32(&m.missedKAs))
}

func (m *Manager) HealthCheck() interfaces.HealthStatus {
	status := m.Module.HealthCheck()
	status.Details["state"] = m.sm.Get().String()
	if lastErr := m.sm.LastError(); lastErr != nil {
		status.Details["last_error"] = lastErr.Error()
	}
	status.Details["server"] = m.config.ServerAddr
	if rtt := time.Duration(atomic.LoadInt64(&m.qualityRTTEWMA)); rtt > 0 {
		status.Details["quality_rtt_ms"] = rtt.Milliseconds()
		status.Details["quality_missed_kas"] = atomic.LoadInt32(&m.missedKAs)
	}
	return status
}

func (m *Manager) Stats() (bytesUp, bytesDown uint64) {
	return atomic.LoadUint64(&m.bytesUp), atomic.LoadUint64(&m.bytesDown)
}
