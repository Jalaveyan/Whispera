package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	singlog "github.com/sagernet/sing/common/logger"

	xmux "github.com/sagernet/sing-mux"
	singM "github.com/sagernet/sing/common/metadata"

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
	gate        decoyActivity
	once        sync.Once
	denyChecked bool
	upLeft      int
}

func (d *decoyLeaveConn) NetConn() net.Conn {
	if nc, ok := d.Conn.(interface{ NetConn() net.Conn }); ok {
		return nc.NetConn()
	}
	return nil
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
		if d.gate != nil {
			d.gate.Leave()
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

	keepAlive := protocol.KeepAliveEnabled()

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

	raw := protocol.NetConnOf(conn)
	splice := wantSplice && protocol.SpliceEnabled() && raw != nil && !protocol.FullFrameEnabled()

	hdrProto := proto
	if keepAlive {
		hdrProto |= protocol.KeepAliveProtoBit
	}
	if splice {
		hdrProto |= protocol.SpliceProtoBit
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
	if !keepAlive {
		return &decoyLeaveConn{Conn: conn, gate: m.config.DecoyGate, upLeft: upstreamShapedWrites}, nil
	}
	base := conn
	if !reused {
		base = &decoyLeaveConn{Conn: conn, upLeft: upstreamShapedWrites}
	}
	up := protocol.NewFramedConn(base)
	down := up
	stream := &keepAliveStream{Conn: base, up: up, down: down, m: m, base: base}
	if splice {
		stream.down = protocol.NewFramedConn(raw)
		stream.raw = raw
	}
	return stream, nil
}

const (
	upstreamMaxPayload   = 480
	upstreamShapedWrites = 8
)

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
	return &decoyLeaveConn{Conn: conn, gate: m.config.DecoyGate, upLeft: upstreamShapedWrites}, nil
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
