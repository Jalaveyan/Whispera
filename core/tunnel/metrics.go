package tunnel

import (
	"sync/atomic"
	"time"

	"github.com/nekoskin/whispera/common/runtime/interfaces"
)

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
