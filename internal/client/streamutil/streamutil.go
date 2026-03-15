package streamutil

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

func ReadFrame(conn net.Conn) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(lenBuf)
	if length == 0 {
		return []byte{}, nil
	}
	if length > 1<<20 {
		return nil, fmt.Errorf("frame too large: %d", length)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}

	return data, nil
}

func WriteFrame(conn net.Conn, data []byte) error {
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))

	bufs := net.Buffers{lenBuf, data}
	_, err := bufs.WriteTo(conn)
	return err
}

func SafeUint16(n int) (uint16, bool) {
	if n < 0 || n > 65535 {
		return 0, false
	}
	return uint16(n), true
}
