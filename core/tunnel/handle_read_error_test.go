package tunnel

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestHandleReadErrorTriggersReconnect(t *testing.T) {
	m := newTestManager(t)
	m.config.ServerAddr = "127.0.0.1:1"
	m.config.ServerAddrTCP = "127.0.0.1:1"
	m.config.Transport = "tcp"
	m.config.ConnectionTimeout = 150 * time.Millisecond

	mc := &managedConn{closing: make(chan struct{})}
	m.connMu.Lock()
	m.activeConn = mc
	m.activePool = []*managedConn{mc}
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
	t.Fatal("handleReadError did not trigger Reconnect() after a read error on the last pool connection")
}

func TestHandleReadErrorFailsOverWithSiblings(t *testing.T) {
	m := newTestManager(t)
	m.setState(StateConnected)

	dead := &managedConn{closing: make(chan struct{})}
	alive := &managedConn{closing: make(chan struct{})}
	m.connMu.Lock()
	m.activeConn = dead
	m.activePool = []*managedConn{dead, alive}
	m.connMu.Unlock()

	m.handleReadError(dead, errors.New("read tcp: connection reset by peer"))

	time.Sleep(50 * time.Millisecond)
	if atomic.LoadUint32(&m.reconnectAttempts) != 0 {
		t.Fatal("failover must not trigger a full reconnect while the pool has healthy siblings")
	}
	m.connMu.RLock()
	poolLen := len(m.activePool)
	active := m.activeConn
	m.connMu.RUnlock()
	if poolLen != 1 {
		t.Fatalf("pool len = %d, want 1 (dead conn dropped)", poolLen)
	}
	if active != alive {
		t.Fatal("active conn should be promoted to the surviving sibling")
	}
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
