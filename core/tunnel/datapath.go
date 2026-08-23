package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	singlog "github.com/sagernet/sing/common/logger"

	xmux "github.com/sagernet/sing-mux"
	singM "github.com/sagernet/sing/common/metadata"

	"github.com/nekoskin/whispera/common/buf"
	"github.com/nekoskin/whispera/core/protocol"
)

type camoDialer struct{ m *Manager }

func (d camoDialer) DialContext(ctx context.Context, network string, dest singM.Socksaddr) (net.Conn, error) {
	dial := d.m.dial()
	if dial == nil {
		return nil, fmt.Errorf("stream-mux: no whispera dialer")
	}
	return dial(ctx)
}

func (d camoDialer) ListenPacket(ctx context.Context, dest singM.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("stream-mux: udp not supported")
}

func (m *Manager) getStreamMuxClient() (*xmux.Client, error) {
	m.smMu.Lock()
	defer m.smMu.Unlock()
	if m.smClient != nil {
		return m.smClient, nil
	}
	c, err := xmux.NewClient(xmux.Options{
		Dialer:   camoDialer{m},
		Logger:   singlog.NOP(),
		Protocol: "smux",
	})
	if err != nil {
		return nil, err
	}
	m.smClient = c
	return c, nil
}

type decoyLeaveConn struct {
	net.Conn
	m           *Manager
	once        sync.Once
	denyChecked bool
	upLeft      int
}

func (d *decoyLeaveConn) Read(b []byte) (int, error) {
	n, err := d.Conn.Read(b)
	if !d.denyChecked {
		d.denyChecked = true
		if msg, ok := protocol.ParseDenial(b[:n]); ok {
			d.Conn.Close()
			return 0, errors.New("whispera: " + msg)
		}
	}
	return n, err
}

func (d *decoyLeaveConn) Write(b []byte) (int, error) {
	return d.writeShaped(b)
}

func (d *decoyLeaveConn) writeShaped(b []byte) (int, error) {
	written := 0
	for len(b) > 0 {
		n := len(b)
		if d.upLeft > 0 && n > upstreamMaxPayload {
			n = upstreamMaxPayload
		}
		c, err := d.Conn.Write(b[:n])
		written += c
		if err != nil {
			return written, err
		}
		if d.upLeft > 0 {
			d.upLeft--
		}
		b = b[n:]
	}
	return written, nil
}

func (d *decoyLeaveConn) Close() error {
	d.once.Do(func() {
		if d.m.config.DecoyGate != nil {
			d.m.config.DecoyGate.Leave()
		}
	})
	return d.Conn.Close()
}

func (m *Manager) connectPerFlow(ctx context.Context) error {
	dial := m.dial()
	if dial == nil {
		err := fmt.Errorf("direct: no camo dialer")
		m.setError(err)
		return err
	}
	probe, err := dial(ctx)
	if err != nil {
		m.setError(err)
		return err
	}
	probe.Close()

	m.setState(StateConnected)
	m.connMu.Lock()
	m.connectedAt = time.Now()
	m.connMu.Unlock()

	m.selector.startDatagramLane()
	return nil
}

func (m *Manager) openStreamPerFlow(ctx context.Context, proto byte, addr string, port uint16) (net.Conn, error) {
	dial := m.dial()
	if dial == nil {
		return nil, fmt.Errorf("direct: no camo dialer")
	}
	wantSplice := proto&protocol.SpliceProtoBit != 0
	proto &^= protocol.SpliceProtoBit

	keepAlive := !wantSplice && protocol.KeepAliveEnabled()

	var conn net.Conn
	reused := false
	if keepAlive {
		if c := m.idle.take(); c != nil {
			conn, reused = c, true
		}
	}
	if conn == nil {
		c, err := dial(ctx)
		if err != nil {
			if ctx.Err() == nil {
				m.setError(err)
			}
			return nil, fmt.Errorf("direct dial: %w", err)
		}
		conn = c
	}

	splice := wantSplice && protocol.SpliceEnabled()
	var raw net.Conn
	if splice {
		if raw = protocol.NetConnOf(conn); raw == nil {
			splice = false
		}
	}
	hdrProto := proto
	if splice {
		hdrProto |= protocol.SpliceProtoBit
		if protocol.FullFrameEnabled() {
			hdrProto |= protocol.FullFrameProtoBit
		}
	} else if keepAlive {
		hdrProto |= protocol.KeepAliveProtoBit
	}

	addrBytes := []byte(addr)
	header := make([]byte, 1+2+len(addrBytes)+2)
	header[0] = hdrProto
	binary.BigEndian.PutUint16(header[1:3], uint16(len(addrBytes)))
	copy(header[3:], addrBytes)
	binary.BigEndian.PutUint16(header[3+len(addrBytes):], port)
	if _, err := conn.Write(header); err != nil {
		conn.Close()
		return nil, fmt.Errorf("direct connect header: %w", err)
	}

	if m.config.DecoyGate != nil {
		m.config.DecoyGate.Enter()
	}
	if splice {
		dl := &decoyLeaveConn{Conn: conn, m: m, upLeft: upstreamShapedWrites}
		left := spliceRecordsToPad
		if protocol.FullFrameEnabled() {
			left = frameForever
		}
		return &clientSpliceConn{decoyLeaveConn: dl, raw: raw, padLeft: left}, nil
	}
	if !keepAlive {
		return &decoyLeaveConn{Conn: conn, m: m, upLeft: upstreamShapedWrites}, nil
	}
	base := conn
	if !reused {
		base = &decoyLeaveConn{Conn: conn, m: m, upLeft: upstreamShapedWrites}
	}
	return &keepAliveStream{FramedConn: protocol.NewFramedConn(base), m: m, base: base}, nil
}

const (
	spliceRecordsToPad   = 8
	upstreamMaxPayload   = 480
	upstreamShapedWrites = 8
	frameForever         = -1
)

type clientSpliceConn struct {
	*decoyLeaveConn
	raw     net.Conn
	padLeft int
	rbuf    []byte
}

func (c *clientSpliceConn) Write(b []byte) (int, error) {
	return c.decoyLeaveConn.writeShaped(b)
}

func (c *clientSpliceConn) Read(b []byte) (int, error) {
	if len(c.rbuf) > 0 {
		n := copy(b, c.rbuf)
		c.rbuf = c.rbuf[n:]
		return n, nil
	}
	if c.padLeft == 0 {
		return c.raw.Read(b)
	}
	// The server fills silence with records that carry no data, so the shape of
	// the stream does not depend on the site having something to say. They are
	// framing, not payload — read past them.
	for {
		n, err := c.readRecord(b)
		if n > 0 || err != nil || c.padLeft == 0 {
			return n, err
		}
	}
}

func (c *clientSpliceConn) SpliceTo(dst net.Conn) (int64, error) {
	var total int64
	pre := make([]byte, upstreamMaxPayload*32)
	for c.padLeft != 0 || len(c.rbuf) > 0 {
		rn, rerr := c.Read(pre)
		if rn > 0 {
			wn, werr := dst.Write(pre[:rn])
			total += int64(wn)
			if werr != nil {
				return total, werr
			}
		}
		if rerr != nil {
			return total, rerr
		}
	}
	if d, s := buf.RawTCP(dst), buf.RawTCP(c.raw); d != nil && s != nil {
		n, err := d.ReadFrom(s)
		if err != nil {
			if noter, ok := c.raw.(interface{ Note(error) }); ok {
				noter.Note(err)
			}
		}
		return total + n, err
	}
	n, err := io.Copy(dst, c.raw)
	return total + n, err
}

func (c *clientSpliceConn) readRecord(b []byte) (int, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(c.raw, hdr[:]); err != nil {
		return 0, err
	}
	if hdr[0] != 0x17 {
		return 0, fmt.Errorf("splice: bad record type 0x%02x", hdr[0])
	}
	body := int(binary.BigEndian.Uint16(hdr[3:5]))
	rec := make([]byte, body)
	if _, err := io.ReadFull(c.raw, rec); err != nil {
		return 0, err
	}
	if c.padLeft > 0 {
		c.padLeft--
	}
	if body < 2 {
		return 0, fmt.Errorf("splice: short record")
	}
	dataLen := int(binary.BigEndian.Uint16(rec[0:2]))
	if 2+dataLen > body {
		return 0, fmt.Errorf("splice: bad data len")
	}
	data := rec[2 : 2+dataLen]
	n := copy(b, data)
	if n < len(data) {
		c.rbuf = append(c.rbuf[:0], data[n:]...)
	}
	return n, nil
}

func (m *Manager) connectStreamMux(ctx context.Context) error {
	if _, err := m.getStreamMuxClient(); err != nil {
		m.setError(err)
		return err
	}
	dial := m.dial()
	if dial == nil {
		err := fmt.Errorf("stream-mux: no whispera dialer")
		m.setError(err)
		return err
	}
	probe, err := dial(ctx)
	if err != nil {
		m.setError(err)
		return err
	}
	probe.Close()

	m.setState(StateConnected)
	m.connMu.Lock()
	m.connectedAt = time.Now()
	m.connMu.Unlock()
	log.Warn("stream-mux mode active (h2mux) — yamux pool bypassed")
	return nil
}

func (m *Manager) openStreamMux(ctx context.Context, proto byte, addr string, port uint16) (net.Conn, error) {
	c, err := m.getStreamMuxClient()
	if err != nil {
		return nil, err
	}
	conn, err := c.DialContext(ctx, "tcp", singM.ParseSocksaddrHostPort(addr, port))
	if err != nil {
		if ctx.Err() == nil {
			m.setError(err)
		}
		return nil, fmt.Errorf("stream-mux dial: %w", err)
	}
	if _, err := conn.Write([]byte{proto}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("stream-mux proto write: %w", err)
	}
	if m.config.DecoyGate != nil {
		m.config.DecoyGate.Enter()
	}
	return &decoyLeaveConn{Conn: conn, m: m, upLeft: upstreamShapedWrites}, nil
}

func (m *Manager) OpenStream(ctx context.Context, proto byte, addr string, port uint16) (net.Conn, error) {
	if protocol.StreamMuxEnabled() {
		return m.openStreamMux(ctx, proto, addr, port)
	}
	return m.openStreamPerFlow(ctx, proto, addr, port)
}

const (
	protoTCP = 0x06
	protoUDP = 0x11
)

func (m *Manager) dial() func(context.Context) (net.Conn, error) { return m.selector.dial() }

func (m *Manager) GetState() TunnelState { return m.sm.Get() }
