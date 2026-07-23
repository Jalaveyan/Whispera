package tunnel

import (
	"bytes"
	"net"
	"testing"
	"time"
)

type spliceReadConn struct {
	net.Conn
	r *bytes.Reader
}

func (c *spliceReadConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func buildSplicePaddedWire(payloads [][]byte) []byte {
	var w bytes.Buffer
	for _, p := range payloads {
		const pad = 20
		body := 2 + len(p) + pad
		w.Write([]byte{0x17, 0x03, 0x03, byte(body >> 8), byte(body)})
		w.Write([]byte{byte(len(p) >> 8), byte(len(p))})
		w.Write(p)
		w.Write(make([]byte, pad))
	}
	return w.Bytes()
}

func readAllSmall(t *testing.T, c net.Conn, chunk int) []byte {
	t.Helper()
	var out bytes.Buffer
	buf := make([]byte, chunk)
	for {
		n, err := c.Read(buf)
		out.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return out.Bytes()
}

func newClientSplice(wire []byte) *clientSpliceConn {
	return &clientSpliceConn{
		decoyLeaveConn: &decoyLeaveConn{},
		raw:            &spliceReadConn{r: bytes.NewReader(wire)},
		padLeft:        spliceRecordsToPad,
	}
}

func TestClientSpliceShortResponseSmallBuffers(t *testing.T) {
	payloads := [][]byte{[]byte("hello"), []byte("world!!"), bytes.Repeat([]byte("x"), 200)}
	csc := newClientSplice(buildSplicePaddedWire(payloads))
	got := readAllSmall(t, csc, 3)
	want := bytes.Join(payloads, nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("mismatch: got %q, want %q", got, want)
	}
}

func TestClientSplicePaddedThenRaw(t *testing.T) {
	var payloads [][]byte
	for i := 0; i < spliceRecordsToPad; i++ {
		payloads = append(payloads, bytes.Repeat([]byte{byte('a' + i)}, 13))
	}
	wire := buildSplicePaddedWire(payloads)
	tail := bytes.Repeat([]byte("RAW"), 100)
	wire = append(wire, tail...)

	csc := newClientSplice(wire)
	got := readAllSmall(t, csc, 7)
	want := append(bytes.Join(payloads, nil), tail...)
	if !bytes.Equal(got, want) {
		t.Fatalf("mismatch: got %d bytes, want %d", len(got), len(want))
	}
}

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
