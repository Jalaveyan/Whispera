package tunnel

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// Regression test for a bug where handleReadError called m.sm.SetError(err)
// (which moves the state machine to StateError) and then checked
// m.GetState() == StateConnected before triggering Reconnect() — a check
// that was always false right after SetError, so Reconnect() was dead code
// on every real read error (RST, broken pipe, EOF...).
func TestHandleReadErrorTriggersReconnect(t *testing.T) {
	m := newTestManager(t)
	m.config.ServerAddr = "127.0.0.1:1"
	m.config.ServerAddrTCP = "127.0.0.1:1"
	m.config.Transport = "tcp"
	m.config.ConnectionTimeout = 150 * time.Millisecond

	mc := &managedConn{closing: make(chan struct{})}
	m.connMu.Lock()
	m.activeConn = mc
	m.connMu.Unlock()
	m.setState(StateConnected)

	m.handleReadError(mc, errors.New("read tcp: connection reset by peer"))

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadUint32(&m.reconnectAttempts) > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("handleReadError did not trigger Reconnect() after a non-timeout read error on the active connection")
}

func TestHandleReadErrorIgnoresTimeout(t *testing.T) {
	m := newTestManager(t)
	mc := &managedConn{closing: make(chan struct{})}
	m.connMu.Lock()
	m.activeConn = mc
	m.connMu.Unlock()
	m.setState(StateConnected)

	m.handleReadError(mc, &timeoutErr{})

	time.Sleep(50 * time.Millisecond)
	if got := m.GetState(); got != StateConnected {
		t.Errorf("GetState() = %v after a read-deadline timeout, want unchanged %v", got, StateConnected)
	}
}

// Same bug as TestHandleReadErrorTriggersReconnect, but for the
// forceReconnectFromStreamFailure path (connect-ack timeout / stream write
// failure), which had its own copy of the SetError-then-recheck mistake.
func TestForceReconnectFromStreamFailureTriggersReconnect(t *testing.T) {
	m := newTestManager(t)
	m.config.ServerAddr = "127.0.0.1:1"
	m.config.ServerAddrTCP = "127.0.0.1:1"
	m.config.Transport = "tcp"
	m.config.ConnectionTimeout = 150 * time.Millisecond

	mc := &managedConn{closing: make(chan struct{})}
	m.connMu.Lock()
	m.activeConn = mc
	m.connMu.Unlock()
	m.setState(StateConnected)

	m.forceReconnectFromStreamFailure(mc, "connect ack timeout")

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadUint32(&m.reconnectAttempts) > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("forceReconnectFromStreamFailure did not trigger Reconnect()")
}

type timeoutErr struct{}

func (*timeoutErr) Error() string   { return "i/o timeout" }
func (*timeoutErr) Timeout() bool   { return true }
func (*timeoutErr) Temporary() bool { return true }
