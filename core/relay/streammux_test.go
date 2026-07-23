package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	xmux "github.com/sagernet/sing-mux"
	singM "github.com/sagernet/sing/common/metadata"
)

type tcpDialer struct{ addr string }

func (d tcpDialer) DialContext(ctx context.Context, network string, dest singM.Socksaddr) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", d.addr)
}
func (d tcpDialer) ListenPacket(ctx context.Context, dest singM.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("no udp")
}

func startEcho(t *testing.T) net.Listener {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c)
		}
	}()
	return ln
}

func startUDPEcho(t *testing.T) net.PacketConn {
	pc, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc
}

func startMuxServer(t *testing.T) net.Listener {
	s, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		var id uint64
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			id++
			go s.serveStreamMux(c, "test", id)
		}
	}()
	return ln
}

func TestStreamMuxEndToEnd(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	srv := startMuxServer(t)
	defer srv.Close()

	client, err := xmux.NewClient(xmux.Options{
		Dialer:     tcpDialer{srv.Addr().String()},
		Protocol:   "smux",
		MaxStreams: 16,
	})
	if err != nil {
		t.Fatal(err)
	}

	// три параллельных стрима через один мукс — echo-корректность
	for n := 0; n < 3; n++ {
		conn, err := client.DialContext(context.Background(), "tcp", singM.ParseSocksaddr(echo.Addr().String()))
		if err != nil {
			t.Fatalf("dial stream %d: %v", n, err)
		}
		if _, err := conn.Write([]byte{0x06}); err != nil {
			t.Fatalf("proto write %d: %v", n, err)
		}
		msg := []byte("hello-mux-stream")
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("write %d: %v", n, err)
		}
		got := make([]byte, len(msg))
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("read %d: %v", n, err)
		}
		if string(got) != string(msg) {
			t.Fatalf("stream %d echo mismatch: got %q", n, got)
		}
		conn.Close()
	}
}

func TestStreamMuxUDP(t *testing.T) {
	echo := startUDPEcho(t)
	defer echo.Close()
	srv := startMuxServer(t)
	defer srv.Close()

	client, err := xmux.NewClient(xmux.Options{
		Dialer:     tcpDialer{srv.Addr().String()},
		Protocol:   "smux",
		MaxStreams: 16,
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.DialContext(context.Background(), "tcp", singM.ParseSocksaddr(echo.LocalAddr().String()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// proto-маркер UDP, затем 2-байтовый датаграмм-фрейм (как SOCKS5-UDP)
	if _, err := conn.Write([]byte{0x11}); err != nil {
		t.Fatalf("proto write: %v", err)
	}
	payload := []byte("udp-datagram-hello")
	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
	copy(frame[2:], payload)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("frame write: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("read hdr: %v", err)
	}
	sz := binary.BigEndian.Uint16(hdr)
	got := make([]byte, sz)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("udp echo mismatch: got %q want %q", got, payload)
	}
}

func TestStreamMuxThroughput(t *testing.T) {
	// sink target: reads everything, discards
	sink, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	go func() {
		for {
			c, err := sink.Accept()
			if err != nil {
				return
			}
			go io.Copy(io.Discard, c)
		}
	}()

	srv := startMuxServer(t)
	defer srv.Close()

	client, err := xmux.NewClient(xmux.Options{
		Dialer:     tcpDialer{srv.Addr().String()},
		Protocol:   "smux",
		MaxStreams: 16,
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.DialContext(context.Background(), "tcp", singM.ParseSocksaddr(sink.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{0x06}); err != nil {
		t.Fatalf("proto write: %v", err)
	}
	payload := make([]byte, 256*1024)
	var total int64
	start := time.Now()
	deadline := start.Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n, err := conn.Write(payload)
		if err != nil {
			t.Fatalf("write: %v", err)
		}
		total += int64(n)
	}
	mbps := float64(total) * 8 / time.Since(start).Seconds() / 1e6
	t.Logf("stream-mux throughput (loopback): %.0f Mbps (%.0f MB)", mbps, float64(total)/1024/1024)
	if total == 0 {
		t.Fatal("no data transferred through stream-mux path")
	}
}

type spliceFakeConn struct {
	net.Conn
	out *bytes.Buffer
	tx  int
}

func (c *spliceFakeConn) Write(p []byte) (int, error) { return c.out.Write(p) }
func (c *spliceFakeConn) CountTx(n int)               { c.tx += n }

func decodeSpliceWire(t *testing.T, raw []byte, padRecords int) []byte {
	t.Helper()
	var out bytes.Buffer
	off := 0
	for i := 0; i < padRecords; i++ {
		if off+5 > len(raw) {
			break
		}
		if raw[off] != 0x17 {
			t.Fatalf("record %d: type 0x%02x, want 0x17", i, raw[off])
		}
		body := int(binary.BigEndian.Uint16(raw[off+3 : off+5]))
		off += 5
		if off+body > len(raw) {
			t.Fatalf("record %d: truncated", i)
		}
		dataLen := int(binary.BigEndian.Uint16(raw[off : off+2]))
		if 2+dataLen > body {
			t.Fatalf("record %d: data len %d exceeds body %d", i, dataLen, body)
		}
		out.Write(raw[off+2 : off+2+dataLen])
		off += body
	}
	out.Write(raw[off:])
	return out.Bytes()
}

func TestServerSplicePaddingRoundTrip(t *testing.T) {
	fc := &spliceFakeConn{out: &bytes.Buffer{}}
	sc := &serverSpliceConn{Conn: fc, raw: fc, padLeft: spliceRecordsToPad}

	writes := [][]byte{
		bytes.Repeat([]byte("A"), 10),
		bytes.Repeat([]byte("B"), 100),
		bytes.Repeat([]byte("C"), spliceMaxData+1000),
		bytes.Repeat([]byte("D"), 50000),
	}
	var sent bytes.Buffer
	for _, w := range writes {
		n, err := sc.Write(w)
		if err != nil || n != len(w) {
			t.Fatalf("Write() = (%d, %v), want (%d, nil)", n, err, len(w))
		}
		sent.Write(w)
	}

	got := decodeSpliceWire(t, fc.out.Bytes(), spliceRecordsToPad)
	if !bytes.Equal(got, sent.Bytes()) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), sent.Len())
	}
	if fc.tx != sent.Len() {
		t.Errorf("CountTx total = %d, want %d", fc.tx, sent.Len())
	}
}
