package tunnel

import (
	"testing"
	"time"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := New(DefaultConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return m
}

func TestNewInitialState(t *testing.T) {
	m := newTestManager(t)

	if got := m.GetState(); got != StateDisconnected {
		t.Errorf("GetState() = %v, want %v", got, StateDisconnected)
	}
	if m.IsConnected() {
		t.Error("IsConnected() = true on fresh Manager")
	}
	if m.GetSessionID() != 0 {
		t.Errorf("GetSessionID() = %d, want 0", m.GetSessionID())
	}
}

func TestDisconnectOnFreshManagerIsSafe(t *testing.T) {
	m := newTestManager(t)

	m.Disconnect()

	if got := m.GetState(); got != StateDisconnected {
		t.Errorf("GetState() after Disconnect() = %v, want %v", got, StateDisconnected)
	}
}

func TestQualityMetrics(t *testing.T) {
	m := newTestManager(t)

	rtt, missed := m.GetQualityMetrics()
	if rtt != 0 || missed != 0 {
		t.Errorf("GetQualityMetrics() = (%v, %d), want (0, 0) on fresh Manager", rtt, missed)
	}

	m.updateQualityRTT(50 * time.Millisecond)
	rtt, _ = m.GetQualityMetrics()
	if rtt != 50*time.Millisecond {
		t.Errorf("GetQualityMetrics() rtt = %v, want %v after first sample", rtt, 50*time.Millisecond)
	}
}

func TestStats(t *testing.T) {
	m := newTestManager(t)

	up, down := m.Stats()
	if up != 0 || down != 0 {
		t.Errorf("Stats() = (%d, %d), want (0, 0) on fresh Manager", up, down)
	}
}

func TestTransportGetSet(t *testing.T) {
	m := newTestManager(t)

	m.SetTransport("quic")
	if got := m.GetTransport(); got != "quic" {
		t.Errorf("GetTransport() = %q, want %q", got, "quic")
	}
}

func TestRateLimitGetSet(t *testing.T) {
	m := newTestManager(t)

	m.SetRateLimit(1024)
	if got := m.GetRateLimit(); got != 1024 {
		t.Errorf("GetRateLimit() = %d, want 1024", got)
	}
}

func TestTLSFragmentSizeGetSet(t *testing.T) {
	m := newTestManager(t)

	m.SetTLSFragmentSize(40)
	if got := m.GetTLSFragmentSize(); got != 40 {
		t.Errorf("GetTLSFragmentSize() = %d, want 40", got)
	}

	m.SetTLSFragmentSize(-5)
	if got := m.GetTLSFragmentSize(); got != 0 {
		t.Errorf("GetTLSFragmentSize() = %d, want 0 after negative input", got)
	}
}

func TestForceObfuscationGetSet(t *testing.T) {
	m := newTestManager(t)

	m.SetForceObfuscation(true)
	if !m.IsForceObfuscation() {
		t.Error("IsForceObfuscation() = false after SetForceObfuscation(true)")
	}

	m.SetForceObfuscation(false)
	if m.IsForceObfuscation() {
		t.Error("IsForceObfuscation() = true after SetForceObfuscation(false)")
	}
}

func TestSetBehavioralProfileWithoutObfuscator(t *testing.T) {
	m := newTestManager(t)
	m.obfuscator = nil

	if err := m.SetBehavioralProfile("steady"); err == nil {
		t.Error("SetBehavioralProfile() error = nil, want error when obfuscator is nil")
	}
	if err := m.SetBehavioralProfile(""); err == nil {
		t.Error("SetBehavioralProfile(\"\") error = nil, want error when obfuscator is nil")
	}
}

func TestHealthCheck(t *testing.T) {
	m := newTestManager(t)

	status := m.HealthCheck()
	if status.Details["state"] != StateDisconnected.String() {
		t.Errorf("HealthCheck() state = %v, want %v", status.Details["state"], StateDisconnected.String())
	}
}
