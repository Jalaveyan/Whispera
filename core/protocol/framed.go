package protocol

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
)

const KeepAliveProtoBit byte = 0x20

const (
	framedWireTarget = 5 + 16384 + 1 + 16
	framedMaxData    = framedWireTarget - 5 - 2
)

var errFramedBadRecord = errors.New("whispera: bad framed record")

type FramedConn struct {
	net.Conn

	rmu  sync.Mutex
	rbuf []byte
	done bool

	wmu   sync.Mutex
	batch []byte
	ended bool
}

func NewFramedConn(c net.Conn) *FramedConn {
	return &FramedConn{Conn: c, batch: make([]byte, 0, framedWireTarget)}
}

func (c *FramedConn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.ended {
		return 0, io.ErrClosedPipe
	}
	sent := 0
	for len(b) > 0 {
		n := len(b)
		if n > framedMaxData {
			n = framedMaxData
		}
		out := c.batch[:0]
		out = append(out, 0x17, 0x03, 0x03)
		out = binary.BigEndian.AppendUint16(out, uint16(2+n))
		out = binary.BigEndian.AppendUint16(out, uint16(n))
		out = append(out, b[:n]...)
		if _, err := c.Conn.Write(out); err != nil {
			c.batch = out[:0]
			return sent, err
		}
		c.batch = out[:0]
		sent += n
		b = b[n:]
	}
	return sent, nil
}

func (c *FramedConn) Read(b []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(c.rbuf) > 0 {
		n := copy(b, c.rbuf)
		c.rbuf = c.rbuf[n:]
		return n, nil
	}
	if c.done {
		return 0, io.EOF
	}
	data, err := c.readRecord()
	if err != nil {
		return 0, err
	}
	if len(data) == 0 {
		c.done = true
		return 0, io.EOF
	}
	n := copy(b, data)
	if n < len(data) {
		c.rbuf = append(c.rbuf[:0], data[n:]...)
	}
	return n, nil
}

func (c *FramedConn) readRecord() ([]byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 0x17 {
		return nil, errFramedBadRecord
	}
	body := int(binary.BigEndian.Uint16(hdr[3:5]))
	if body < 2 || body > framedWireTarget {
		return nil, errFramedBadRecord
	}
	rec := make([]byte, body)
	if _, err := io.ReadFull(c.Conn, rec); err != nil {
		return nil, err
	}
	dataLen := int(binary.BigEndian.Uint16(rec[0:2]))
	if 2+dataLen > body {
		return nil, errFramedBadRecord
	}
	return rec[2 : 2+dataLen], nil
}

func (c *FramedConn) EndStream() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.ended {
		return nil
	}
	c.ended = true
	_, err := c.Conn.Write([]byte{0x17, 0x03, 0x03, 0x00, 0x02, 0x00, 0x00})
	return err
}

func (c *FramedConn) StreamDone() bool {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	return c.done
}

func (c *FramedConn) Reusable() bool {
	c.rmu.Lock()
	done := c.done
	c.rmu.Unlock()
	c.wmu.Lock()
	ended := c.ended
	c.wmu.Unlock()
	return done && ended
}

func (c *FramedConn) Close() error { return c.EndStream() }

func (c *FramedConn) CloseUnderlying() error { return c.Conn.Close() }

func (c *FramedConn) Reset() {
	c.rmu.Lock()
	c.done = false
	c.rbuf = nil
	c.rmu.Unlock()
	c.wmu.Lock()
	c.ended = false
	c.wmu.Unlock()
}
