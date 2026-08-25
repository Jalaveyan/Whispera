package tunnel

import (
	"bytes"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nekoskin/whispera/core/protocol"
)

type spliceReadConn struct {
	net.Conn
	r *bytes.Reader
}

func (c *spliceReadConn) Read(b []byte) (int, error) { return c.r.Read(b) }

type spliceWriteConn struct {
	net.Conn
	w bytes.Buffer
}

func (c *spliceWriteConn) Write(b []byte) (int, error) { return c.w.Write(b) }

func framedRecord(data []byte, marker int) []byte {
	const pad = 20
	body := 2 + len(data) + pad
	out := []byte{0x17, 0x03, 0x03, byte(body >> 8), byte(body)}
	if marker >= 0 {
		out = append(out, byte(marker>>8), byte(marker))
	} else {
		out = append(out, byte(len(data)>>8), byte(len(data)))
	}
	out = append(out, data...)
	return append(out, make([]byte, pad)...)
}

func buildFramedWire(payloads [][]byte) []byte {
	var w bytes.Buffer
	for _, p := range payloads {
		w.Write(framedRecord(p, -1))
	}
	return w.Bytes()
}

func newKeepAliveStream(wire []byte) (*keepAliveStream, *spliceWriteConn) {
	src := &spliceReadConn{r: bytes.NewReader(wire)}
	fc := protocol.NewFramedConn(src)
	return &keepAliveStream{Conn: src, up: fc, down: fc, base: src, raw: src}, &spliceWriteConn{}
}

func TestKeepAliveStreamShortResponseStaysFramed(t *testing.T) {
	payloads := [][]byte{[]byte("hello"), []byte("world!!"), bytes.Repeat([]byte("x"), 200)}
	ks, dst := newKeepAliveStream(buildFramedWire(payloads))

	if _, err := ks.SpliceTo(dst); err != nil {
		t.Fatalf("SpliceTo() error = %v", err)
	}
	want := bytes.Join(payloads, nil)
	if !bytes.Equal(dst.w.Bytes(), want) {
		t.Fatalf("mismatch: got %q, want %q", dst.w.Bytes(), want)
	}
}

func TestKeepAliveStreamFollowsSwitchToRaw(t *testing.T) {
	payloads := [][]byte{[]byte("page"), bytes.Repeat([]byte("y"), 300)}
	wire := buildFramedWire(payloads)
	wire = append(wire, framedRecord(nil, 0xFFFF)...)
	tail := bytes.Repeat([]byte("RAW"), 100)
	wire = append(wire, tail...)

	ks, dst := newKeepAliveStream(wire)

	if _, err := ks.SpliceTo(dst); err != nil {
		t.Fatalf("SpliceTo() error = %v", err)
	}
	want := append(bytes.Join(payloads, nil), tail...)
	if !bytes.Equal(dst.w.Bytes(), want) {
		t.Fatalf("mismatch: got %d bytes, want %d", dst.w.Len(), len(want))
	}
	if ks.down.StreamDone() {
		t.Error("stream marked done after following the switch to raw")
	}
}

type poolConn struct {
	net.Conn
	r      *bytes.Reader
	closed atomic.Bool
}

func (c *poolConn) Read(b []byte) (int, error)  { return c.r.Read(b) }
func (c *poolConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *poolConn) Close() error                { c.closed.Store(true); return nil }

func (c *poolConn) SetReadDeadline(time.Time) error { return nil }

// Wire the server sends for a short answer: data records, then the end marker.
func shortAnswerWire(payloads [][]byte) []byte {
	var w bytes.Buffer
	for _, p := range payloads {
		w.Write(framedRecord(p, -1))
	}
	w.Write(framedRecord(nil, 0))
	return w.Bytes()
}

func TestKeepAliveStreamReturnsConnectionToPool(t *testing.T) {
	m := newTestManager(t)
	base := &poolConn{r: bytes.NewReader(shortAnswerWire([][]byte{[]byte("page"), []byte("body")}))}
	fc := protocol.NewFramedConn(base)
	ks := &keepAliveStream{Conn: base, up: fc, down: fc, m: m, base: base}

	var got bytes.Buffer
	sink := &spliceWriteConn{}
	if _, err := ks.SpliceTo(sink); err != nil {
		t.Fatalf("SpliceTo() error = %v", err)
	}
	got.Write(sink.w.Bytes())
	if got.String() != "pagebody" {
		t.Fatalf("payload = %q, want %q", got.String(), "pagebody")
	}

	if err := ks.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	// The connection joins the set once the drain finishes, which is off the
	// closing path.
	pooled := 0
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		m.idle.mu.Lock()
		pooled = len(m.idle.conns)
		m.idle.mu.Unlock()
		if pooled == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if base.closed.Load() {
		t.Error("connection was closed instead of pooled")
	}
	if pooled != 1 {
		t.Fatalf("idleSet holds %d connections, want 1: without pooling the next stream pays a full handshake", pooled)
	}
}

func TestKeepAliveStreamDiscardsUnfinishedStream(t *testing.T) {
	m := newTestManager(t)
	base := &poolConn{r: bytes.NewReader(framedRecord([]byte("partial"), -1))}
	fc := protocol.NewFramedConn(base)
	ks := &keepAliveStream{Conn: base, up: fc, down: fc, m: m, base: base}

	var one [4]byte
	if _, err := ks.Read(one[:]); err != nil && err != io.EOF {
		t.Fatalf("Read() error = %v", err)
	}
	_ = ks.Close()

	// Draining happens off the closing path, so give it a moment: an unfinished
	// stream must end up closed, never in the set where the next user would read
	// someone else's tail.
	deadline := time.Now().Add(2 * time.Second)
	for !base.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !base.closed.Load() {
		t.Error("connection stayed open after an unfinished stream")
	}
	m.idle.mu.Lock()
	pooled := len(m.idle.conns)
	m.idle.mu.Unlock()
	if pooled != 0 {
		t.Errorf("idleSet holds %d connections: an unfinished stream was pooled", pooled)
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

func TestHelloSplitDisabledByDefault(t *testing.T) {
	t.Setenv("WHISPERA_HELLO_SPLIT", "")
	if helloSplitEnabled() {
		t.Fatal("outer ClientHello split must be off by default (one-segment invariant under tail-drop DPI)")
	}
	t.Setenv("WHISPERA_HELLO_SPLIT", "1")
	if !helloSplitEnabled() {
		t.Fatal("WHISPERA_HELLO_SPLIT=1 must enable outer ClientHello split")
	}
}
