package protocol

import (
	"encoding/binary"
	"errors"
	"io"
	mrand "math/rand"
	"net"
	"sync"
	"sync/atomic"
)

const KeepAliveProtoBit byte = 0x20

const (
	framedWireTarget  = 5 + 16384 + 1 + 16
	framedPlainTarget = 16384
	framedMaxData     = framedPlainTarget - 5 - 2

	shapePadMin     = 111
	shapePadMax     = 1111
	shapePadRecords = 3

	framedSwitchMarker = 0xFFFF
)

func ShapePadLen(room int) int {
	if room <= 0 {
		return 0
	}
	pad := shapePadMin + mrand.Intn(shapePadMax-shapePadMin+1)
	if pad > room {
		pad = room
	}
	return pad
}

func AppendShapePad(out []byte, n int) []byte {
	if n <= 0 {
		return out
	}
	start := len(out)
	out = append(out, make([]byte, n)...)
	for i := start; i < len(out); i += 8 {
		var word [8]byte
		binary.BigEndian.PutUint64(word[:], mrand.Uint64())
		copy(out[i:], word[:])
	}
	return out
}

// ShapeBudget is how many records still get padded, counted per connection
// rather than per stream. A keep-alive connection has no "first few records"
// after every request, so restarting the count for each stream drew the same
// opening pattern over and over on one socket.
type ShapeBudget struct{ left atomic.Int32 }

func NewShapeBudget() *ShapeBudget {
	b := &ShapeBudget{}
	b.left.Store(shapePadRecords)
	return b
}

func (b *ShapeBudget) take() bool {
	if b == nil {
		return false
	}
	for {
		v := b.left.Load()
		if v <= 0 {
			return false
		}
		if b.left.CompareAndSwap(v, v-1) {
			return true
		}
	}
}

var errFramedBadRecord = errors.New("whispera: bad framed record")

var ErrSwitchRaw = errors.New("whispera: framed switched to raw")

type FramedConn struct {
	net.Conn

	rmu  sync.Mutex
	rbuf []byte
	rrec []byte
	done bool

	wmu      sync.Mutex
	batch    []byte
	ended    bool
	switched bool
	pad      *ShapeBudget
}

func NewFramedConn(c net.Conn, pad *ShapeBudget) *FramedConn {
	// The batch buffer is grown on the first write: half of these connections
	// only ever read — the upstream half of a spliced stream, for one — and a
	// 16K buffer each adds up once streams come in thousands.
	return &FramedConn{Conn: c, pad: pad}
}

func (c *FramedConn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.ended {
		return 0, io.ErrClosedPipe
	}
	if c.batch == nil {
		c.batch = make([]byte, 0, framedPlainTarget)
	}
	sent := 0
	for len(b) > 0 {
		n := len(b)
		if n > framedMaxData {
			n = framedMaxData
		}
		pad := 0
		if c.pad.take() {
			pad = ShapePadLen(framedMaxData - n)
		}
		out := c.batch[:0]
		out = append(out, 0x17, 0x03, 0x03)
		out = binary.BigEndian.AppendUint16(out, uint16(2+n+pad))
		out = binary.BigEndian.AppendUint16(out, uint16(n))
		out = append(out, b[:n]...)
		out = AppendShapePad(out, pad)
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
	if cap(c.rrec) < body {
		c.rrec = make([]byte, body)
	}
	rec := c.rrec[:body]
	if _, err := io.ReadFull(c.Conn, rec); err != nil {
		return nil, err
	}
	dataLen := int(binary.BigEndian.Uint16(rec[0:2]))
	if dataLen == framedSwitchMarker {
		return nil, ErrSwitchRaw
	}
	if 2+dataLen > body {
		return nil, errFramedBadRecord
	}
	return rec[2 : 2+dataLen], nil
}

func (c *FramedConn) SwitchRaw() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.ended {
		return nil
	}
	c.ended, c.switched = true, true
	return c.writeMarker(framedSwitchMarker)
}

func (c *FramedConn) SwitchedRaw() bool {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.switched
}

func (c *FramedConn) writeMarker(marker uint16) error {
	pad := 0
	if c.pad.take() {
		pad = ShapePadLen(framedMaxData)
	}
	out := make([]byte, 0, 5+2+pad)
	out = append(out, 0x17, 0x03, 0x03)
	out = binary.BigEndian.AppendUint16(out, uint16(2+pad))
	out = binary.BigEndian.AppendUint16(out, marker)
	out = AppendShapePad(out, pad)
	_, err := c.Conn.Write(out)
	return err
}

func (c *FramedConn) EndStream() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.ended {
		return nil
	}
	c.ended = true
	return c.writeMarker(0)
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
	ended, switched := c.ended, c.switched
	c.wmu.Unlock()
	return done && ended && !switched
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
