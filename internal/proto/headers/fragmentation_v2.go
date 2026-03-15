package headers

import (
	"encoding/binary"
	"errors"
)


type CompactFragmentHeader struct {
	Flags    byte
	FragID   uint32
	FragIdx  uint16
	FragCnt  uint16
	StreamID uint16
	ChunkLen uint16
}

const (
	FragFlagLast       byte = 1 << 0
	FragFlagHasStream  byte = 1 << 1
	FragFlagLargeChunk byte = 1 << 2
	FragFlagLargeCount byte = 1 << 3
)

const (
	CompactFragmentHeaderMinLen = 6
	CompactFragmentHeaderMaxLen = 11
)

func (f *CompactFragmentHeader) MarshalBinary() ([]byte, error) {
	hasStream := f.StreamID != 0
	largeChunk := f.ChunkLen > 255
	largeCount := f.FragCnt > 255

	headerLen := 1
	headerLen += 3
	headerLen += 2
	if largeCount {
		headerLen += 2
	} else {
		headerLen += 1
	}
	if hasStream {
		headerLen += 2
	}
	if largeChunk {
		headerLen += 2
	} else {
		headerLen += 1
	}

	buf := make([]byte, headerLen)
	offset := 0

	flags := Version2 << 5
	if largeCount {
		flags |= FragFlagLargeCount << 2
	}
	if largeChunk {
		flags |= FragFlagLargeChunk << 2
	}
	if hasStream {
		flags |= FragFlagHasStream << 2
	}
	if f.Flags&FragFlagLast != 0 {
		flags |= FragFlagLast << 2
	}
	buf[offset] = flags
	offset++

	buf[offset] = byte(f.FragID >> 16)
	buf[offset+1] = byte(f.FragID >> 8)
	buf[offset+2] = byte(f.FragID)
	offset += 3

	binary.BigEndian.PutUint16(buf[offset:offset+2], f.FragIdx)
	offset += 2

	if largeCount {
		buf[offset] = 0xFF
		binary.BigEndian.PutUint16(buf[offset+1:offset+3], f.FragCnt)
		offset += 3
	} else {
		buf[offset] = byte(f.FragCnt)
		offset += 1
	}

	if hasStream {
		binary.BigEndian.PutUint16(buf[offset:offset+2], f.StreamID)
		offset += 2
	}

	if largeChunk {
		buf[offset] = 0xFF
		binary.BigEndian.PutUint16(buf[offset+1:offset+3], f.ChunkLen)
	} else {
		buf[offset] = byte(f.ChunkLen)
	}

	return buf, nil
}

func (f *CompactFragmentHeader) UnmarshalBinary(b []byte) error {
	if len(b) < CompactFragmentHeaderMinLen {
		return errors.New("short fragment header")
	}

	offset := 0

	flags := b[offset]
	version := (flags >> 5) & 0x07
	if version != Version2 {
		return errors.New("version mismatch")
	}
	f.Flags = flags & 0x1F
	largeCount := (flags & (FragFlagLargeCount << 2)) != 0
	largeChunk := (flags & (FragFlagLargeChunk << 2)) != 0
	hasStream := (flags & (FragFlagHasStream << 2)) != 0
	isLast := (flags & (FragFlagLast << 2)) != 0
	if isLast {
		f.Flags |= FragFlagLast
	}
	offset++

	f.FragID = uint32(b[offset])<<16 | uint32(b[offset+1])<<8 | uint32(b[offset+2])
	offset += 3

	f.FragIdx = binary.BigEndian.Uint16(b[offset : offset+2])
	offset += 2

	if largeCount || (b[offset] == 0xFF && len(b) > offset+2) {
		if len(b) < offset+3 {
			return errors.New("short fragment count")
		}
		f.FragCnt = binary.BigEndian.Uint16(b[offset+1 : offset+3])
		offset += 3
	} else {
		f.FragCnt = uint16(b[offset])
		offset += 1
	}

	if hasStream {
		if len(b) < offset+2 {
			return errors.New("short stream id")
		}
		f.StreamID = binary.BigEndian.Uint16(b[offset : offset+2])
		offset += 2
	} else {
		f.StreamID = 0
	}

	if largeChunk {
		if len(b) < offset+3 || b[offset] != 0xFF {
			return errors.New("invalid large chunk length")
		}
		f.ChunkLen = binary.BigEndian.Uint16(b[offset+1 : offset+3])
	} else {
		if len(b) <= offset {
			return errors.New("short chunk length")
		}
		f.ChunkLen = uint16(b[offset])
	}

	return nil
}

func FragmentPacketV2(payload []byte, maxChunkSize int, streamID uint16) ([]Fragment, error) {
	if len(payload) == 0 {
		return nil, errors.New("empty payload")
	}

	avgOverhead := 24
	effectiveChunkSize := maxChunkSize - avgOverhead

	if effectiveChunkSize <= 0 {
		return nil, errors.New("max chunk size too small")
	}

	fragID := uint32(len(payload)) ^ uint32(streamID)
	fragCnt := (len(payload) + effectiveChunkSize - 1) / effectiveChunkSize

	if fragCnt > 65535 {
		return nil, errors.New("too many fragments")
	}

	fragments := make([]Fragment, 0, fragCnt)

	for i := 0; i < fragCnt; i++ {
		start := i * effectiveChunkSize
		end := start + effectiveChunkSize
		if end > len(payload) {
			end = len(payload)
		}

		chunk := payload[start:end]
		chunkLen := uint16(len(chunk))

		isLast := (i == fragCnt-1)

		header := &CompactFragmentHeader{
			Flags:    0,
			FragID:   fragID,
			FragIdx:  uint16(i),
			FragCnt:  uint16(fragCnt),
			StreamID: streamID,
			ChunkLen: chunkLen,
		}

		if isLast {
			header.Flags |= FragFlagLast
		}

		frag := Fragment{
			Header:   header,
			Chunk:    chunk,
			IsLast:   isLast,
			StreamID: streamID,
		}

		fragments = append(fragments, frag)
	}

	return fragments, nil
}

type Fragment struct {
	Header   *CompactFragmentHeader
	Chunk    []byte
	IsLast   bool
	StreamID uint16
}

func MarshalFragment(frag Fragment) ([]byte, error) {
	headerBytes, err := frag.Header.MarshalBinary()
	if err != nil {
		return nil, err
	}

	result := make([]byte, len(headerBytes)+len(frag.Chunk))
	copy(result, headerBytes)
	copy(result[len(headerBytes):], frag.Chunk)

	return result, nil
}

func UnmarshalFragment(data []byte) (*Fragment, error) {
	header := &CompactFragmentHeader{}

	var headerLen int
	for i := CompactFragmentHeaderMinLen; i <= CompactFragmentHeaderMaxLen && i <= len(data); i++ {
		if err := header.UnmarshalBinary(data[:i]); err == nil {
			headerLen = i
			break
		}
	}

	if headerLen == 0 {
		return nil, errors.New("failed to unmarshal fragment header")
	}

	if len(data) < headerLen+int(header.ChunkLen) {
		return nil, errors.New("short fragment data")
	}

	chunk := data[headerLen : headerLen+int(header.ChunkLen)]

	frag := &Fragment{
		Header:   header,
		Chunk:    chunk,
		IsLast:   (header.Flags & FragFlagLast) != 0,
		StreamID: header.StreamID,
	}

	return frag, nil
}

func CalculateFragmentOverhead(maxPacketSize int, streamID uint16) (int, int) {
	avgOverhead := 24

	effectiveChunkSize := maxPacketSize - avgOverhead
	if effectiveChunkSize <= 0 {
		return 0, 0
	}

	return avgOverhead, effectiveChunkSize
}
