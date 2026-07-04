package protocol

import (
	"context"
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

	SetForcedRawFingerprint(raw)
	defer SetForcedRawFingerprint(nil)
	id, spec, _ := pickFingerprint()
	if id != utls.HelloCustom || spec == nil {
		t.Fatalf("pickFingerprint did not return the raw spec: id=%v spec=%v", id, spec)
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
