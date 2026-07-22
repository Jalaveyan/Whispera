package protocol

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func captureClientHello(t *testing.T, id utls.ClientHelloID) []byte {
	t.Helper()
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	go func() {
		u := utls.UClient(cli, &utls.Config{ServerName: "x.example", InsecureSkipVerify: true}, id)
		_ = u.BuildHandshakeState()
		_ = u.HandshakeContext(context.Background())
	}()
	srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	ph, err := peekClientHello(srv)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	return ph.raw
}

func TestRawFingerprintStoreAndForce(t *testing.T) {
	raw := captureClientHello(t, utls.HelloChrome_133)
	dir := t.TempDir()

	if err := PersistRawFingerprint(dir, raw); err != nil {
		t.Fatalf("persist: %v", err)
	}
	got, ok := FreshestRawFingerprint(dir, "chrome")
	if !ok || len(got) == 0 {
		t.Fatalf("freshest chrome not found (classify=%v)", classifyClientHello(raw))
	}

	replayable := captureClientHello(t, utls.HelloChrome_120)
	SetForcedRawFingerprint(replayable)
	id, spec, _ := pickFingerprint()
	if id != utls.HelloCustom || spec == nil {
		t.Fatalf("pickFingerprint did not return the raw spec: id=%v spec=%v", id, spec)
	}
	SetForcedRawFingerprint(nil)

	SetForcedRawFingerprint(raw)
	defer SetForcedRawFingerprint(nil)
	forcedRawMu.RLock()
	fb := forcedRawBytes
	forcedRawMu.RUnlock()
	if fb != nil {
		t.Fatalf("hybrid PQ capture should be rejected as forced-raw")
	}
}

type helloWriteRecorder struct {
	net.Conn
	writes [][]byte
}

func (w *helloWriteRecorder) Write(b []byte) (int, error) {
	w.writes = append(w.writes, append([]byte(nil), b...))
	return len(b), nil
}

func TestHelloSplitConnSplitsFirstWrite(t *testing.T) {
	rec := &helloWriteRecorder{}
	c := &helloSplitConn{Conn: rec, splitAt: 5}
	if n, err := c.Write([]byte("0123456789")); err != nil || n != 10 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if len(rec.writes) != 2 {
		t.Fatalf("first write not split: %d parts", len(rec.writes))
	}
	if string(rec.writes[0]) != "01234" || string(rec.writes[1]) != "56789" {
		t.Fatalf("bad split: %q %q", rec.writes[0], rec.writes[1])
	}
	if _, err := c.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if len(rec.writes) != 3 || string(rec.writes[2]) != "abc" {
		t.Fatalf("later write should pass through unsplit: %v", rec.writes)
	}
}

func TestHelloSplitConnPassthrough(t *testing.T) {
	for _, off := range []int{0, -1, 100} {
		rec := &helloWriteRecorder{}
		c := &helloSplitConn{Conn: rec, splitAt: off}
		if _, err := c.Write([]byte("short")); err != nil {
			t.Fatal(err)
		}
		if len(rec.writes) != 1 {
			t.Fatalf("offset %d: expected passthrough, got %d parts", off, len(rec.writes))
		}
	}
}

type pipeWriteCounter struct {
	net.Conn
	count int
}

func (w *pipeWriteCounter) Write(b []byte) (int, error) {
	w.count++
	return w.Conn.Write(b)
}

func TestHelloSplitPreservesClientHello(t *testing.T) {
	for _, off := range []int{0, 30, 80} {
		cli, srv := net.Pipe()
		rec := &pipeWriteCounter{Conn: cli}
		var send net.Conn = rec
		if off > 0 {
			send = &helloSplitConn{Conn: rec, splitAt: off}
		}
		go func() {
			u := utls.UClient(send, &utls.Config{ServerName: "x.example", InsecureSkipVerify: true}, utls.HelloChrome_133)
			_ = u.BuildHandshakeState()
			_ = u.HandshakeContext(context.Background())
		}()
		srv.SetReadDeadline(time.Now().Add(2 * time.Second))
		ph, err := peekClientHello(srv)
		cli.Close()
		srv.Close()
		if err != nil {
			t.Fatalf("off=%d peek: %v", off, err)
		}
		if len(ph.raw) < 5 || utls.UnmarshalClientHello(ph.raw[5:]) == nil {
			t.Fatalf("off=%d: split corrupted the ClientHello", off)
		}
		wantParts := 1
		if off > 0 {
			wantParts = 2
		}
		if rec.count < wantParts {
			t.Fatalf("off=%d: expected >=%d writes, got %d", off, wantParts, rec.count)
		}
	}
}

func TestHelloSplitRealHandshake(t *testing.T) {
	for _, host := range []string{"cloudflare.com", "www.google.com"} {
		for _, off := range []int{0, 25, 64} {
			raw, err := (&net.Dialer{Timeout: 8 * time.Second}).DialContext(context.Background(), "tcp", host+":443")
			if err != nil {
				t.Skipf("dial %s: %v", host, err)
			}
			var conn net.Conn = raw
			if off > 0 {
				conn = &helloSplitConn{Conn: raw, splitAt: off}
			}
			u := utls.UClient(conn, &utls.Config{ServerName: host}, utls.HelloChrome_Auto)
			if err := u.BuildHandshakeState(); err != nil {
				raw.Close()
				t.Skipf("build: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			err = u.HandshakeContext(ctx)
			cancel()
			raw.Close()
			if err != nil {
				t.Errorf("split=%d %s: handshake failed: %v", off, host, err)
			}
		}
	}
}

func TestClassifyHandshake(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		latency time.Duration
		want    HandshakeResult
	}{
		{"success", nil, 50 * time.Millisecond, HandshakeOK},
		{"reset_fast", errors.New("read tcp 1.2.3.4:443: connection reset by peer"), 5 * time.Millisecond, HandshakeResetFast},
		{"reset_slow", errors.New("connection reset by peer"), 200 * time.Millisecond, HandshakeError},
		{"decode", errors.New("remote error: tls: error decoding message"), 40 * time.Millisecond, HandshakeRejected},
		{"bad_cert", errors.New("tls: bad certificate"), 60 * time.Millisecond, HandshakeRejected},
		{"deadline", errors.New("context deadline exceeded"), 4 * time.Second, HandshakeIncomplete},
		{"io_timeout", errors.New("read tcp: i/o timeout"), 4 * time.Second, HandshakeIncomplete},
		{"other", errors.New("some unknown failure"), 100 * time.Millisecond, HandshakeError},
	}
	for _, c := range cases {
		if got := classifyHandshake(c.err, c.latency); got != c.want {
			t.Errorf("%s: classifyHandshake = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestHandshakeResultReward(t *testing.T) {
	if HandshakeOK.Reward() != 1.0 {
		t.Fatalf("OK reward = %v, want 1.0", HandshakeOK.Reward())
	}
	if HandshakeResetFast.Reward() != -1.0 {
		t.Fatalf("ResetFast reward = %v, want -1.0", HandshakeResetFast.Reward())
	}
	ordered := []HandshakeResult{HandshakeResetFast, HandshakeRejected, HandshakeIncomplete, HandshakeError, HandshakeOK}
	for i := 1; i < len(ordered); i++ {
		if ordered[i-1].Reward() >= ordered[i].Reward() {
			t.Fatalf("reward not strictly increasing in severity: %v(%.2f) >= %v(%.2f)",
				ordered[i-1], ordered[i-1].Reward(), ordered[i], ordered[i].Reward())
		}
	}
}

func TestHandshakeStrategyConverges(t *testing.T) {
	strategy := NewHandshakeStrategy()
	ctx := "AS12345"
	bestArm := 2
	for i := 0; i < 2000; i++ {
		_, arm := strategy.SelectSplit(ctx)
		r := HandshakeResetFast
		if arm == bestArm {
			r = HandshakeOK
		}
		strategy.Observe(ctx, arm, r)
	}
	if _, arm := strategy.SelectSplit(ctx); arm != bestArm {
		t.Fatalf("did not converge to best arm: picked %d, want %d", arm, bestArm)
	}
}

func TestHandshakeStrategyIsContextual(t *testing.T) {
	strategy := NewHandshakeStrategy()
	best := map[string]int{"AS1": 1, "AS2": 3}
	for i := 0; i < 2000; i++ {
		for ctx, b := range best {
			_, arm := strategy.SelectSplit(ctx)
			r := HandshakeResetFast
			if arm == b {
				r = HandshakeOK
			}
			strategy.Observe(ctx, arm, r)
		}
	}
	for ctx, b := range best {
		if _, arm := strategy.SelectSplit(ctx); arm != b {
			t.Fatalf("context %s did not learn its own best arm %d: picked %d", ctx, b, arm)
		}
	}
}

func TestHandshakeStrategyDemoUnderBlock(t *testing.T) {
	survivingOffset := 24
	censor := func(offset int) HandshakeResult {
		if offset == survivingOffset {
			return HandshakeOK
		}
		return HandshakeResetFast
	}

	strategy := NewHandshakeStrategy()
	ctx := "AS29182/RU"
	cumOK := 0

	dump := func(round int) {
		strategy.mu.Lock()
		sum, cnt := strategy.sum[ctx], strategy.cnt[ctx]
		line := ""
		for i, off := range splitOffsets {
			line += fmt.Sprintf("off=%-2d mean=%+.2f n=%-4d | ", off, armMean(sum[i], cnt[i]), cnt[i])
		}
		strategy.mu.Unlock()
		t.Logf("round=%-4d cum-success=%.2f  %s", round, float64(cumOK)/float64(round), line)
	}

	for round := 1; round <= 3000; round++ {
		offset, arm := strategy.SelectSplit(ctx)
		res := censor(offset)
		strategy.Observe(ctx, arm, res)
		if res == HandshakeOK {
			cumOK++
		}
		if round%500 == 0 {
			dump(round)
		}
	}

	adaptiveOK := 0
	for i := 0; i < 300; i++ {
		offset, _ := strategy.SelectSplit(ctx)
		if censor(offset) == HandshakeOK {
			adaptiveOK++
		}
	}
	fixedOK := 0
	for i := 0; i < 300; i++ {
		if censor(splitOffsets[0]) == HandshakeOK {
			fixedOK++
		}
	}
	_, bestArm := strategy.SelectSplit(ctx)
	t.Logf("LEARNED best offset = %d (survivor = %d)", splitOffsets[bestArm], survivingOffset)
	t.Logf("PROOF: fixed no-split success = %d/300 (%.0f%%) | adaptive success = %d/300 (%.0f%%)",
		fixedOK, 100*float64(fixedOK)/300, adaptiveOK, 100*float64(adaptiveOK)/300)

	if splitOffsets[bestArm] != survivingOffset {
		t.Fatalf("strategy did not learn the surviving offset")
	}
	if adaptiveOK <= fixedOK {
		t.Fatalf("adaptive did not beat the fixed baseline")
	}
}

func TestHandshakeStrategyObserveOutOfRange(t *testing.T) {
	strategy := NewHandshakeStrategy()
	strategy.Observe("ctx", -1, HandshakeOK)
	strategy.Observe("ctx", 999, HandshakeOK)
	if _, arm := strategy.SelectSplit("ctx"); arm < 0 || arm >= len(splitOffsets) {
		t.Fatalf("SelectSplit returned invalid arm %d", arm)
	}
}

func TestFreshestPicksNewest(t *testing.T) {
	dir := t.TempDir()
	older := captureClientHello(t, utls.HelloChrome_131)
	newer := captureClientHello(t, utls.HelloChrome_133)
	if err := PersistRawFingerprint(dir, older); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := PersistRawFingerprint(dir, newer); err != nil {
		t.Fatal(err)
	}
	got, ok := FreshestRawFingerprint(dir, "chrome")
	if !ok {
		t.Fatal("no chrome found")
	}
	if string(got) != string(newer) {
		t.Fatal("freshest should be the most recently stored chrome hello")
	}
}
