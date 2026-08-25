package tunnel

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/nekoskin/whispera/common/buf"
	"github.com/nekoskin/whispera/core/protocol"
)

const keepAliveMaxIdle = 16

type idleSet struct {
	mu    sync.Mutex
	conns []net.Conn
}

func idleAlive(c net.Conn) bool {
	if err := c.SetReadDeadline(time.Now()); err != nil {
		return false
	}
	var probe [1]byte
	_, err := c.Read(probe[:])
	if rerr := c.SetReadDeadline(time.Time{}); rerr != nil {
		return false
	}
	return errors.Is(err, os.ErrDeadlineExceeded)
}

func (s *idleSet) take() net.Conn {
	for {
		s.mu.Lock()
		if len(s.conns) == 0 {
			s.mu.Unlock()
			return nil
		}
		last := len(s.conns) - 1
		c := s.conns[last]
		s.conns = s.conns[:last]
		s.mu.Unlock()

		if idleAlive(c) {
			return c
		}
		c.Close()
	}
}

func (s *idleSet) put(c net.Conn) {
	s.mu.Lock()
	if len(s.conns) >= keepAliveMaxIdle {
		s.mu.Unlock()
		c.Close()
		return
	}
	s.conns = append(s.conns, c)
	s.mu.Unlock()
}

func (s *idleSet) closeAll() {
	s.mu.Lock()
	conns := s.conns
	s.conns = nil
	s.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

type keepAliveStream struct {
	net.Conn
	up   *protocol.FramedConn
	down *protocol.FramedConn
	m    *Manager
	base net.Conn
	raw  net.Conn
	once sync.Once
}

func (c *keepAliveStream) Write(b []byte) (int, error) { return c.up.Write(b) }

func (c *keepAliveStream) Read(b []byte) (int, error) { return c.down.Read(b) }

func (c *keepAliveStream) SpliceTo(dst net.Conn) (int64, error) {
	n, err := buf.Copy(buf.NewReader(c.down), buf.NewWriter(dst))
	if !errors.Is(err, protocol.ErrSwitchRaw) {
		return n, err
	}
	src := c.raw
	if src == nil {
		src = c.base
	}
	if d, s := buf.RawTCP(dst), buf.RawTCP(src); d != nil && s != nil {
		m, rerr := d.ReadFrom(s)
		return n + m, rerr
	}
	m, rerr := io.Copy(dst, src)
	return n + m, rerr
}

func (c *keepAliveStream) Close() error {
	var err error
	c.once.Do(func() {
		if c.m.config.DecoyGate != nil {
			defer c.m.config.DecoyGate.Leave()
		}
		err = c.up.EndStream()
		if err != nil || !c.down.StreamDone() {
			c.base.Close()
			return
		}
		c.m.idle.put(c.base)
	})
	return err
}
