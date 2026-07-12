package protocol

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"
	"testing"
	"time"

	mux2 "whispera/common/mux"
)

func TestSplitHLSSegmentRollover(t *testing.T) {
	t.Setenv("WHISPERA_SPLIT", "1")
	secret := bytes.Repeat([]byte{0x5a}, 32)
	dir := t.TempDir()
	certPath, keyPath := genSelfSigned(t, dir)
	lnAddr := freePort(t)

	const payloadSize = 20 * 1024 * 1024
	payload := make([]byte, payloadSize)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	wantSum := sha256.Sum256(payload)

	onConn := func(conn net.Conn, userID string, sec []byte) {
		sess, err := mux2.Server(mux2.NewPaddedConn(conn, 128), &mux2.Config{MaxStreamBuffer: 1 << 20})
		if err != nil {
			return
		}
		stream, err := sess.AcceptStream()
		if err != nil {
			return
		}
		io.Copy(stream, bytes.NewReader(payload))
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
	stream.Write([]byte("go"))

	got := make([]byte, payloadSize)
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(stream, got)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("read payload: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("timed out reading 20MB across segments")
	}

	gotSum := sha256.Sum256(got)
	if gotSum != wantSum {
		t.Fatalf("payload mismatch after multi-segment download")
	}
}
