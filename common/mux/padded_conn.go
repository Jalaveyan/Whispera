package mux

import (
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"
	"whispera/common/buf"
)

type PaddedConn struct {
	net.Conn
	writeMu   sync.Mutex
	readMu    sync.Mutex
	readBuf   []byte
	maxPad    int
	headerBuf [4]byte
}

func NewPaddedConn(conn net.Conn, maxPad int) *PaddedConn {
	if maxPad <= 0 {
		maxPad = 128
	}
	return &PaddedConn{
		Conn:   conn,
		maxPad: maxPad,
	}
}

func (pc *PaddedConn) Write(p []byte) (int, error) {
	pc.writeMu.Lock()
	defer pc.writeMu.Unlock()

	dataLen := len(p)
	if dataLen > 65000 {
		written := 0
		for written < dataLen {
			chunk := dataLen - written
			if chunk > 65000 {
				chunk = 65000
			}
			if err := pc.writeFrame(p[written : written+chunk]); err != nil {
				return written, err
			}
			written += chunk
		}
		return written, nil
	}
	return dataLen, pc.writeFrame(p)
}

func (pc *PaddedConn) writeFrame(data []byte) error {
	padLen := pc.computePad(len(data))
	if allowed := 65533 - len(data); padLen > allowed {
		padLen = allowed
	}
	if padLen < 0 {
		padLen = 0
	}
	totalLen := 2 + len(data) + padLen
	frameSize := 2 + totalLen

	b := buf.NewSize(frameSize)
	defer b.Release()
	frame := b.Extend(frameSize)

	binary.BigEndian.PutUint16(frame[0:2], uint16(totalLen))
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(data)))
	copy(frame[4:], data)
	if padLen > 0 {
		if _, err := crand.Read(frame[4+len(data):]); err != nil {
			_ = err
		}
	}

	_, err := pc.Conn.Write(frame)
	return err
}

func (pc *PaddedConn) computePad(dataLen int) int {
	wireBase := 4 + dataLen

	additive := rand.Intn(pc.maxPad + 1)

	multiplicative := 0
	if wireBase > 0 {
		multiplicative = rand.Intn(wireBase/2 + 1)
	}

	total := additive + multiplicative
	if max := 65000 - dataLen; total > max {
		total = max
	}
	if total < 0 {
		total = 0
	}
	return total
}

func (pc *PaddedConn) Read(p []byte) (int, error) {
	pc.readMu.Lock()
	defer pc.readMu.Unlock()

	if len(pc.readBuf) > 0 {
		n := copy(p, pc.readBuf)
		pc.readBuf = pc.readBuf[n:]
		return n, nil
	}
	if len(p) == 0 {
		return 0, nil
	}

	for {
		if _, err := io.ReadFull(pc.Conn, pc.headerBuf[:2]); err != nil {
			return 0, err
		}
		totalLen := int(binary.BigEndian.Uint16(pc.headerBuf[:2]))
		if totalLen < 2 || totalLen > 66000 {
			return 0, fmt.Errorf("padded_conn: invalid frame length %d", totalLen)
		}

		b := buf.NewSize(totalLen)
		frameBuf := b.Extend(totalLen)
		if _, err := io.ReadFull(pc.Conn, frameBuf); err != nil {
			b.Release()
			return 0, err
		}

		dataLen := int(binary.BigEndian.Uint16(frameBuf[:2]))
		if dataLen > totalLen-2 {
			b.Release()
			return 0, fmt.Errorf("padded_conn: data length %d exceeds frame %d", dataLen, totalLen)
		}
		if dataLen == 0 {
			b.Release()
			continue
		}

		realData := frameBuf[2 : 2+dataLen]
		n := copy(p, realData)
		if n < dataLen {
			pc.readBuf = append(pc.readBuf[:0], realData[n:]...)
		}
		b.Release()
		return n, nil
	}
}

func (pc *PaddedConn) SetDeadline(t time.Time) error      { return pc.Conn.SetDeadline(t) }
func (pc *PaddedConn) SetReadDeadline(t time.Time) error  { return pc.Conn.SetReadDeadline(t) }
func (pc *PaddedConn) SetWriteDeadline(t time.Time) error { return pc.Conn.SetWriteDeadline(t) }

const (
	rframeData   byte = 0x01
	rframeAck    byte = 0x02
	rframeResume byte = 0x03
)

const (
	resilientMaxUnacked     = 16 << 20
	resilientChunk          = 60000
	resilientMaxFrame       = 1 << 20
	resilientMaxResumeFails = 5
)

type ResilientConn struct {
	nextUnder  func() (net.Conn, error)
	localAddr  net.Addr
	remoteAddr net.Addr

	mu      sync.Mutex
	cond    *sync.Cond
	writeMu sync.Mutex
	under   net.Conn
	closed  bool
	failErr error

	sendSeq     uint64
	sendUnacked uint64
	sendBuf     []byte
	resumeFails int

	recvSeq uint64

	pr *io.PipeReader
	pw *io.PipeWriter
}

func NewResilientConn(local, remote net.Addr, nextUnder func() (net.Conn, error)) *ResilientConn {
	pr, pw := io.Pipe()
	c := &ResilientConn{
		nextUnder:  nextUnder,
		localAddr:  local,
		remoteAddr: remote,
		pr:         pr,
		pw:         pw,
	}
	c.cond = sync.NewCond(&c.mu)
	go c.run()
	return c
}

func (c *ResilientConn) run() {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return
		}
		under := c.under
		c.mu.Unlock()

		if under == nil {
			nu, err := c.nextUnder()
			if err != nil {
				c.fail(err)
				return
			}
			c.mu.Lock()
			if c.closed {
				c.mu.Unlock()
				nu.Close()
				return
			}
			c.under = nu
			c.mu.Unlock()
			under = nu
		}

		if err := c.resume(under); err != nil {
			c.dropUnder(under)
			c.resumeFails++
			if c.resumeFails >= resilientMaxResumeFails {
				c.fail(err)
				return
			}
			continue
		}
		c.resumeFails = 0
		c.readLoop(under)
		c.dropUnder(under)
	}
}

func (c *ResilientConn) resume(under net.Conn) error {
	c.mu.Lock()
	recv := c.recvSeq
	c.mu.Unlock()
	if err := c.writeFrame(under, rframeResume, recv, nil); err != nil {
		return err
	}
	typ, arg, _, err := readResilientFrame(under)
	if err != nil {
		return err
	}
	if typ != rframeResume {
		return fmt.Errorf("resilient: expected resume, got %d", typ)
	}
	return c.retransmit(under, arg)
}

func (c *ResilientConn) retransmit(under net.Conn, peerRecv uint64) error {
	c.mu.Lock()
	if peerRecv < c.sendUnacked || peerRecv > c.sendSeq {
		c.mu.Unlock()
		return fmt.Errorf("resilient: bad resume point %d (unacked %d seq %d)", peerRecv, c.sendUnacked, c.sendSeq)
	}
	if peerRecv > c.sendUnacked {
		c.sendBuf = c.sendBuf[peerRecv-c.sendUnacked:]
		c.sendUnacked = peerRecv
	}
	pending := append([]byte(nil), c.sendBuf...)
	base := c.sendUnacked
	c.mu.Unlock()

	for off := 0; off < len(pending); off += resilientChunk {
		end := off + resilientChunk
		if end > len(pending) {
			end = len(pending)
		}
		if err := c.writeFrame(under, rframeData, base+uint64(off), pending[off:end]); err != nil {
			return err
		}
	}
	return nil
}

func (c *ResilientConn) readLoop(under net.Conn) {
	for {
		typ, arg, payload, err := readResilientFrame(under)
		if err != nil {
			return
		}
		switch typ {
		case rframeData:
			if err := c.deliver(under, arg, payload); err != nil {
				return
			}
		case rframeAck:
			c.mu.Lock()
			if arg > c.sendUnacked && arg <= c.sendSeq {
				c.sendBuf = c.sendBuf[arg-c.sendUnacked:]
				c.sendUnacked = arg
				c.cond.Broadcast()
			}
			c.mu.Unlock()
		}
	}
}

func (c *ResilientConn) deliver(under net.Conn, seq uint64, payload []byte) error {
	c.mu.Lock()
	recv := c.recvSeq
	c.mu.Unlock()

	end := seq + uint64(len(payload))
	if end <= recv {
		return c.writeFrame(under, rframeAck, recv, nil)
	}
	if seq > recv {
		return fmt.Errorf("resilient: gap seq=%d recv=%d", seq, recv)
	}
	if _, err := c.pw.Write(payload[recv-seq:]); err != nil {
		return err
	}
	c.mu.Lock()
	c.recvSeq = end
	recv = c.recvSeq
	c.mu.Unlock()
	return c.writeFrame(under, rframeAck, recv, nil)
}

func (c *ResilientConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	for !c.closed && len(c.sendBuf) >= resilientMaxUnacked {
		c.cond.Wait()
	}
	if c.closed {
		err := c.failErr
		c.mu.Unlock()
		if err == nil {
			err = io.ErrClosedPipe
		}
		return 0, err
	}
	seq := c.sendSeq
	c.sendBuf = append(c.sendBuf, p...)
	c.sendSeq += uint64(len(p))
	under := c.under
	c.mu.Unlock()

	if under != nil {
		_ = c.writeFrame(under, rframeData, seq, p)
	}
	return len(p), nil
}

func (c *ResilientConn) Read(p []byte) (int, error) { return c.pr.Read(p) }

func (c *ResilientConn) writeFrame(under net.Conn, typ byte, arg uint64, payload []byte) error {
	b := make([]byte, 13+len(payload))
	b[0] = typ
	binary.BigEndian.PutUint64(b[1:9], arg)
	binary.BigEndian.PutUint32(b[9:13], uint32(len(payload)))
	copy(b[13:], payload)
	c.writeMu.Lock()
	_, err := under.Write(b)
	c.writeMu.Unlock()
	return err
}

func readResilientFrame(r net.Conn) (typ byte, arg uint64, payload []byte, err error) {
	hdr := make([]byte, 13)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return
	}
	typ = hdr[0]
	arg = binary.BigEndian.Uint64(hdr[1:9])
	n := binary.BigEndian.Uint32(hdr[9:13])
	if n > resilientMaxFrame {
		err = fmt.Errorf("resilient: frame too big %d", n)
		return
	}
	if n > 0 {
		payload = make([]byte, n)
		_, err = io.ReadFull(r, payload)
	}
	return
}

func (c *ResilientConn) dropUnder(under net.Conn) {
	c.mu.Lock()
	if c.under == under {
		c.under = nil
	}
	c.mu.Unlock()
	under.Close()
}

func (c *ResilientConn) fail(err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.failErr = err
	c.cond.Broadcast()
	c.mu.Unlock()
	c.pw.CloseWithError(err)
	c.pr.CloseWithError(err)
}

func (c *ResilientConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	under := c.under
	c.under = nil
	c.cond.Broadcast()
	c.mu.Unlock()
	if under != nil {
		under.Close()
	}
	c.pw.Close()
	c.pr.Close()
	return nil
}

func (c *ResilientConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *ResilientConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *ResilientConn) SetDeadline(t time.Time) error      { return nil }
func (c *ResilientConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *ResilientConn) SetWriteDeadline(t time.Time) error { return nil }

const (
	ResumeEstablish byte = 0x01
	ResumeResume    byte = 0x02
)

const resumeNonceLen = 16
const resumeTokenLen = sha256.Size

func NewResumeNonce() ([]byte, error) {
	n := make([]byte, resumeNonceLen)
	if _, err := crand.Read(n); err != nil {
		return nil, err
	}
	return n, nil
}

func DeriveResumeKey(secret []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("whispera-resilient-resume-v1"))
	return m.Sum(nil)
}

func ResumeToken(sessionKey, nonce []byte, counter uint64) []byte {
	m := hmac.New(sha256.New, sessionKey)
	m.Write(nonce)
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], counter)
	m.Write(c[:])
	return m.Sum(nil)
}

func WriteResumeHeader(w io.Writer, typ byte, payload []byte) error {
	if len(payload) > 0xffff {
		return fmt.Errorf("resilient: resume payload too big %d", len(payload))
	}
	b := make([]byte, 3+len(payload))
	b[0] = typ
	binary.BigEndian.PutUint16(b[1:3], uint16(len(payload)))
	copy(b[3:], payload)
	_, err := w.Write(b)
	return err
}

func ReadResumeHeader(r io.Reader) (typ byte, payload []byte, err error) {
	h := make([]byte, 3)
	if _, err = io.ReadFull(r, h); err != nil {
		return
	}
	typ = h[0]
	n := binary.BigEndian.Uint16(h[1:3])
	if n > 0 {
		payload = make([]byte, n)
		_, err = io.ReadFull(r, payload)
	}
	return
}
