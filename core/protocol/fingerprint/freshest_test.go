package fingerprint

import (
	"context"
	"encoding/binary"
	"io"
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
	var hdr [5]byte
	if _, err := io.ReadFull(srv, hdr[:]); err != nil {
		t.Fatalf("capture header: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:5]))
	if _, err := io.ReadFull(srv, body); err != nil {
		t.Fatalf("capture body: %v", err)
	}
	return append(hdr[:], body...)
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

	got, ok := FreshestRaw(dir, "chrome")
	if !ok {
		t.Fatal("no chrome found")
	}
	if string(got) != string(newer) {
		t.Fatal("freshest should be the most recently stored chrome hello")
	}
}
