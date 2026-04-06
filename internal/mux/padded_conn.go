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
)

// PaddedConn wraps a net.Conn and adds random-length padding to every write,
// making the on-wire frame sizes unpredictable.  This defeats DPI that
// fingerprints yamux by its fixed 12-byte headers / frame structure.
//
// Wire format per frame:
//   [2 bytes: total frame len (big-endian, excludes these 2 bytes)]
//   [2 bytes: real payload len (big-endian)]
//   [payload bytes]
//   [random padding bytes]
//
// Both sides must use PaddedConn for the framing to work.
type PaddedConn struct {
	net.Conn
	writeMu   sync.Mutex
	readMu    sync.Mutex
	readBuf   []byte // buffered leftover from partial reads
	maxPad    int
	headerBuf [4]byte
}

// NewPaddedConn wraps conn with random padding of 0..maxPad bytes per write.
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
		// Split large writes to keep frame size within uint16 range
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
	padLen := rand.Intn(pc.maxPad + 1)
	totalLen := 2 + len(data) + padLen // 2 for real-data-len header

	// Frame: [2: totalLen][2: dataLen][data][padding]
	frame := make([]byte, 2+totalLen)
	binary.BigEndian.PutUint16(frame[0:2], uint16(totalLen))
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(data)))
	copy(frame[4:], data)

	// Fill padding with random bytes
	if padLen > 0 {
		pad := frame[4+len(data):]
		if _, err := crand.Read(pad); err != nil {
			// fallback: just leave zeros, still adds size variation
		}
	}

	_, err := pc.Conn.Write(frame)
	return err
}

func (pc *PaddedConn) Read(p []byte) (int, error) {
	pc.readMu.Lock()
	defer pc.readMu.Unlock()

	// Return buffered data first
	if len(pc.readBuf) > 0 {
		n := copy(p, pc.readBuf)
		pc.readBuf = pc.readBuf[n:]
		return n, nil
	}

	// Read frame header: 2 bytes total length
	if _, err := io.ReadFull(pc.Conn, pc.headerBuf[:2]); err != nil {
		return 0, err
	}
	totalLen := int(binary.BigEndian.Uint16(pc.headerBuf[:2]))
	if totalLen < 2 || totalLen > 66000 {
		return 0, fmt.Errorf("padded_conn: invalid frame length %d", totalLen)
	}

	// Read the full frame
	frameBuf := make([]byte, totalLen)
	if _, err := io.ReadFull(pc.Conn, frameBuf); err != nil {
		return 0, err
	}

	dataLen := int(binary.BigEndian.Uint16(frameBuf[:2]))
	if dataLen > totalLen-2 {
		return 0, fmt.Errorf("padded_conn: data length %d exceeds frame %d", dataLen, totalLen)
	}

	realData := frameBuf[2 : 2+dataLen]
	n := copy(p, realData)
	if n < dataLen {
		// Buffer the rest for next Read call
		pc.readBuf = append(pc.readBuf[:0], realData[n:]...)
	}
	return n, nil
}

func (pc *PaddedConn) SetDeadline(t time.Time) error      { return pc.Conn.SetDeadline(t) }
func (pc *PaddedConn) SetReadDeadline(t time.Time) error   { return pc.Conn.SetReadDeadline(t) }
func (pc *PaddedConn) SetWriteDeadline(t time.Time) error  { return pc.Conn.SetWriteDeadline(t) }
