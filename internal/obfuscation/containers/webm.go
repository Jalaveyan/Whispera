package containers

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"time"
)

type WebMWrapper struct {
	clusterTimecode uint64
	startTime       time.Time
}

func NewWebMWrapper() ContainerWrapper {
	return &WebMWrapper{
		clusterTimecode: 0,
		startTime:       time.Now(),
	}
}

func (w *WebMWrapper) ContentType() string {
	return "video/webm"
}

func (w *WebMWrapper) GetInitSegment() ([]byte, error) {
	buf := new(bytes.Buffer)

	ebmlParams := new(bytes.Buffer)
	writeString(ebmlParams, 0x4286, "webm")
	writeUInt(ebmlParams, 0x42F7, 4)
	writeUInt(ebmlParams, 0x4282, 4)
	writeMaster(buf, 0x1A45DFA3, ebmlParams.Bytes())

	buf.Write([]byte{0x18, 0x53, 0x80, 0x67})
	buf.Write([]byte{0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})

	infoParams := new(bytes.Buffer)
	writeUInt(infoParams, 0x2AD7B1, 1000)
	writeString(infoParams, 0x4D80, "Whispera Muxer")
	writeString(infoParams, 0x5741, "Whispera Writer")
	writeMaster(buf, 0x1549A966, infoParams.Bytes())

	tracksParams := new(bytes.Buffer)

	trackEntry := new(bytes.Buffer)
	writeUInt(trackEntry, 0xD7, 1)
	writeUInt(trackEntry, 0x73C5, 1)
	writeUInt(trackEntry, 0x83, 1)
	writeString(trackEntry, 0x86, "VPN Video")
	writeString(trackEntry, 0x86, "V_VP8")

	videoParams := new(bytes.Buffer)
	writeUInt(videoParams, 0xB0, 1920)
	writeUInt(videoParams, 0xBA, 1080)
	writeMaster(trackEntry, 0xE0, videoParams.Bytes())

	writeMaster(tracksParams, 0xAE, trackEntry.Bytes())
	writeMaster(buf, 0x1654AE6B, tracksParams.Bytes())

	return buf.Bytes(), nil
}

func (w *WebMWrapper) WrapData(data []byte) ([]byte, error) {
	buf := new(bytes.Buffer)

	clusterContent := new(bytes.Buffer)

	writeUInt(clusterContent, 0xE7, w.clusterTimecode)
	w.clusterTimecode += 33

	blockHeader := []byte{0x81, 0x00, 0x00, 0x80}

	tagID := []byte{0xA3}
	size := encodeVINT(uint64(len(blockHeader) + len(data)))

	clusterContent.Write(tagID)
	clusterContent.Write(size)
	clusterContent.Write(blockHeader)
	clusterContent.Write(data)

	writeMaster(buf, 0x1F43B675, clusterContent.Bytes())

	return buf.Bytes(), nil
}

func (w *WebMWrapper) UnwrapData(data []byte) ([]byte, error) {
	reader := bytes.NewReader(data)
	var payloadBuf bytes.Buffer

	for reader.Len() > 0 {
		id, _, err := readVINT(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}

		size, _, err := readVINT(reader)
		if err != nil {
			return nil, err
		}

		contentLen := int64(size)

		if id == 0x1F43B675 {
			continue
		}

		if id == 0xA3 {
			if contentLen <= 4 {
				return nil, errors.New("SimpleBlock too small")
			}

			if _, err := reader.Seek(4, io.SeekCurrent); err != nil {
				return nil, err
			}

			chunk := make([]byte, contentLen-4)
			if _, err := reader.Read(chunk); err != nil {
				return nil, err
			}
			payloadBuf.Write(chunk)
			continue
		}

		if id == 0x18538067 || id == 0x1F43B675 {
			continue
		} else {
			if _, err := reader.Seek(contentLen, io.SeekCurrent); err != nil {
				return nil, err
			}
		}
	}

	return payloadBuf.Bytes(), nil
}

func readVINT(r *bytes.Reader) (uint64, int, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, 0, err
	}

	var width int
	var mask byte

	if b&0x80 != 0 {
		width = 1
		mask = 0x7F
	} else if b&0x40 != 0 {
		width = 2
		mask = 0x3F
	} else if b&0x20 != 0 {
		width = 3
		mask = 0x1F
	} else if b&0x10 != 0 {
		width = 4
		mask = 0x0F
	} else if b&0x08 != 0 {
		width = 5
		mask = 0x07
	} else if b&0x04 != 0 {
		width = 6
		mask = 0x03
	} else if b&0x02 != 0 {
		width = 7
		mask = 0x01
	} else if b&0x01 != 0 {
		width = 8
		mask = 0x00
	} else {
		return 0, 0, errors.New("invalid VINT")
	}

	val := uint64(b & mask)
	for i := 1; i < width; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, 0, err
		}
		val = (val << 8) | uint64(b)
	}

	return val, width, nil
}

func writeMaster(w *bytes.Buffer, id uint32, data []byte) {
	w.Write(encodeID(id))
	w.Write(encodeVINT(uint64(len(data))))
	w.Write(data)
}

func writeUInt(w *bytes.Buffer, id uint32, val uint64) {
	w.Write(encodeID(id))
	var b []byte
	if val <= 0xFF {
		b = []byte{uint8(val)}
	} else if val <= 0xFFFF {
		b = make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(val))
	} else if val <= 0xFFFFFFFF {
		b = make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(val))
	} else {
		b = make([]byte, 8)
		binary.BigEndian.PutUint64(b, val)
	}
	w.Write(encodeVINT(uint64(len(b))))
	w.Write(b)
}

func writeString(w *bytes.Buffer, id uint32, val string) {
	w.Write(encodeID(id))
	w.Write(encodeVINT(uint64(len(val))))
	w.WriteString(val)
}

func encodeID(id uint32) []byte {
	if id < 0x100 {
		return []byte{uint8(id)}
	} else if id < 0x10000 {
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(id))
		return b
	} else {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, id)
		return b
	}
}

func encodeVINT(val uint64) []byte {
	if val < 127 {
		return []byte{uint8(0x80 | val)}
	} else if val < 16383 {
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(0x4000|val))
		return b
	} else if val < 2097151 {
		b := make([]byte, 3)
		val |= 0x200000
		b[0] = byte(val >> 16)
		b[1] = byte(val >> 8)
		b[2] = byte(val)
		return b
	} else {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(0x10000000|val))
		return b
	}
}
