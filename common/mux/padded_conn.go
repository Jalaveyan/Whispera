package mux

import (
	crand "crypto/rand"
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
