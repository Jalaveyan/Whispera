package protocol

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	mux2 "whispera/common/mux"
)

func TestSplitTransportEcho(t *testing.T) {
	t.Setenv("WHISPERA_SPLIT", "1")
	secret := bytes.Repeat([]byte{0x5a}, 32)
	dir := t.TempDir()
	certPath, keyPath := genSelfSigned(t, dir)
	lnAddr := freePort(t)

	onConn := func(conn net.Conn, userID string, sec []byte) {
		sess, err := mux2.Server(mux2.NewPaddedConn(conn, 128), &mux2.Config{MaxStreamBuffer: 1 << 20})
		if err != nil {
			return
		}
		stream, err := sess.AcceptStream()
		if err != nil {
			return
		}
		io.Copy(stream, stream)
		stream.Close()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = ListenAndServe(ctx, &ServerConfig{
			ListenAddr:   lnAddr,
			TLSCert:      certPath,
			TLSKey:       keyPath,
			SharedSecret: secret,
			OnConn:       onConn,
		})
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", lnAddr)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("listener never came up")
		}
		time.Sleep(50 * time.Millisecond)
	}

	fc, err := Client(ctx, &ClientConfig{
		ServerAddr:   lnAddr,
		ServerName:   "example.com",
		SharedSecret: secret,
	})
	if err != nil {
		t.Fatalf("Client (split): %v", err)
	}
	defer fc.Close()

	cli, err := mux2.Client(mux2.NewPaddedConn(fc, 128), &mux2.Config{MaxStreamBuffer: 1 << 20})
	if err != nil {
		t.Fatalf("mux client: %v", err)
	}
	stream, err := cli.OpenStream()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	msg := bytes.Repeat([]byte("whispera-split-"), 8192)
	go func() { stream.Write(msg) }()

	got := make([]byte, len(msg))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo mismatch: got %d bytes of %d", len(got), len(msg))
	}
}
