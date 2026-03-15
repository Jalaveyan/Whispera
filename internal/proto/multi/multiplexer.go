package multi

import (
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"

	"whispera/internal/proto/headers"
	"whispera/internal/util"
)

type StreamMultiplexer struct {
	streams      map[uint16]*Stream
	mu           sync.RWMutex
	nextID       uint32
	maxStreams   int
	streamCount  int32
	totalStreams uint64
}

type Stream struct {
	ID           uint16
	Seq          uint32
	State        StreamState
	Buffer       []byte
	Closed       bool
	LastActivity int64
	BytesIn      uint64
	BytesOut     uint64
	PacketsIn    uint64
	PacketsOut   uint64
	Created      int64
	LocalWindow  uint32
	RemoteWindow uint32
	mu           sync.RWMutex
}

type StreamState byte

const (
	StreamStateOpen StreamState = iota
	StreamStateHalfClosed
	StreamStateClosed
)

const (
	TunStreamID uint16 = 1

	StreamProtoTunAggregate uint8 = 0

	DefaultWindowSize uint32 = 65535
)

type StreamCommand byte

const (
	StreamOpen StreamCommand = 0x01

	StreamData StreamCommand = 0x02

	StreamClose StreamCommand = 0x03

	StreamOpenDomain StreamCommand = 0x09

	StreamWindowUpdate StreamCommand = 0x04
)

type StreamErrorCode byte

const (
	ErrCodeNoError          StreamErrorCode = 0x00
	ErrCodeInternalError    StreamErrorCode = 0x01
	ErrCodeProtocolError    StreamErrorCode = 0x02
	ErrCodeRefused          StreamErrorCode = 0x03
	ErrCodeFlowControlError StreamErrorCode = 0x04
)

type StreamControlFrame struct {
	Command StreamCommand
	Payload []byte
}

func EncodeStreamControlFrame(cmd StreamCommand, payload []byte) []byte {
	out := make([]byte, 1+len(payload))
	out[0] = byte(cmd)
	copy(out[1:], payload)
	return out
}

func DecodeStreamControlFrame(b []byte) (*StreamControlFrame, error) {
	if len(b) == 0 {
		return nil, errors.New("empty stream control frame")
	}
	frame := &StreamControlFrame{
		Command: StreamCommand(b[0]),
	}
	if len(b) > 1 {
		frame.Payload = b[1:]
	}
	return frame, nil
}

func EncodeStreamClose(code StreamErrorCode) []byte {
	return []byte{byte(code)}
}

func DecodeStreamClose(payload []byte) StreamErrorCode {
	if len(payload) == 0 {
		return ErrCodeNoError
	}
	return StreamErrorCode(payload[0])
}

func EncodeStreamWindowUpdate(delta uint32) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, delta)
	return out
}

func DecodeStreamWindowUpdate(payload []byte) (uint32, error) {
	if len(payload) < 4 {
		return 0, errors.New("short window update payload")
	}
	return binary.BigEndian.Uint32(payload), nil
}

func NewStreamMultiplexer() *StreamMultiplexer {
	return &StreamMultiplexer{
		streams:     make(map[uint16]*Stream),
		nextID:      1,
		maxStreams:  0,
		streamCount: 0,
	}
}

func NewStreamMultiplexerWithLimit(maxStreams int) *StreamMultiplexer {
	return &StreamMultiplexer{
		streams:     make(map[uint16]*Stream),
		nextID:      1,
		maxStreams:  maxStreams,
		streamCount: 0,
	}
}

func (m *StreamMultiplexer) AllocateStream() (uint16, error) {
	for {
		id := atomic.AddUint32(&m.nextID, 1)
		if id > 65535 {
			if atomic.CompareAndSwapUint32(&m.nextID, id, 1) {
				id = 1
			} else {
				continue
			}
		}

		streamID := uint16(id)

		m.mu.RLock()
		_, exists := m.streams[streamID]
		m.mu.RUnlock()

		if !exists {
			return streamID, nil
		}
	}
}

func (m *StreamMultiplexer) GetStream(streamID uint16) (*Stream, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stream, exists := m.streams[streamID]
	if exists {
		stream.mu.Lock()
		atomic.StoreInt64(&stream.LastActivity, getCurrentTime())
		stream.mu.Unlock()
	}
	return stream, exists
}

func (m *StreamMultiplexer) GetOrCreateStream(streamID uint16) (*Stream, error) {
	m.mu.RLock()
	if stream, exists := m.streams[streamID]; exists {
		m.mu.RUnlock()
		stream.mu.Lock()
		atomic.StoreInt64(&stream.LastActivity, getCurrentTime())
		stream.mu.Unlock()
		return stream, nil
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	if stream, exists := m.streams[streamID]; exists {
		stream.mu.Lock()
		atomic.StoreInt64(&stream.LastActivity, getCurrentTime())
		stream.mu.Unlock()
		return stream, nil
	}

	if m.maxStreams > 0 {
		currentCount := int(atomic.LoadInt32(&m.streamCount))
		if currentCount >= m.maxStreams {
			return nil, errors.New("maximum stream limit reached")
		}
	}

	now := getCurrentTime()
	stream := &Stream{
		ID:           streamID,
		Seq:          1,
		State:        StreamStateOpen,
		Buffer:       make([]byte, 0, 4096),
		LastActivity: now,
		Created:      now,
		LocalWindow:  DefaultWindowSize,
		RemoteWindow: DefaultWindowSize,
	}

	m.streams[streamID] = stream
	atomic.AddInt32(&m.streamCount, 1)
	atomic.AddUint64(&m.totalStreams, 1)
	return stream, nil
}

func (m *StreamMultiplexer) CloseStream(streamID uint16) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if stream, exists := m.streams[streamID]; exists {
		stream.mu.Lock()
		stream.Closed = true
		stream.State = StreamStateClosed
		stream.mu.Unlock()
		delete(m.streams, streamID)
		atomic.AddInt32(&m.streamCount, -1)
		return true
	}
	return false
}

func (m *StreamMultiplexer) HalfCloseStream(streamID uint16) {
	m.mu.RLock()
	stream, exists := m.streams[streamID]
	m.mu.RUnlock()

	if exists {
		stream.mu.Lock()
		if stream.State == StreamStateOpen {
			stream.State = StreamStateHalfClosed
		}
		stream.mu.Unlock()
	}
}

func (m *StreamMultiplexer) CleanupInactive(timeout int64) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := getCurrentTime()
	removed := 0
	var toRemove []uint16

	for id, stream := range m.streams {
		stream.mu.RLock()
		lastActivity := atomic.LoadInt64(&stream.LastActivity)
		closed := stream.Closed
		state := stream.State
		stream.mu.RUnlock()

		currentTimeout := timeout
		if state == StreamStateHalfClosed && timeout > 0 {
			currentTimeout = timeout / 2
		}

		if closed || (now-lastActivity > currentTimeout) {
			if len(toRemove) < cap(toRemove) {
				toRemove = toRemove[:len(toRemove)+1]
				toRemove[len(toRemove)-1] = id
			} else {
				toRemove = append(toRemove, id)
			}
		}
	}

	for _, id := range toRemove {
		if stream, exists := m.streams[id]; exists {
			stream.mu.Lock()
			stream.Closed = true
			stream.State = StreamStateClosed
			stream.mu.Unlock()
			delete(m.streams, id)
			atomic.AddInt32(&m.streamCount, -1)
			removed++
		}
	}

	return removed
}

func (m *StreamMultiplexer) GetStreamCount() int {
	return int(atomic.LoadInt32(&m.streamCount))
}

func (m *StreamMultiplexer) GetTotalStreams() uint64 {
	return atomic.LoadUint64(&m.totalStreams)
}

func (m *StreamMultiplexer) GetAllStreamIDs() []uint16 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids := make([]uint16, 0, len(m.streams))
	for id := range m.streams {
		if len(ids) < cap(ids) {
			ids = ids[:len(ids)+1]
			ids[len(ids)-1] = id
		} else {
			ids = append(ids, id)
		}
	}
	return ids
}

func (m *StreamMultiplexer) GetStreamStats(streamID uint16) (stats StreamStats, exists bool) {
	m.mu.RLock()
	stream, ok := m.streams[streamID]
	m.mu.RUnlock()

	if !ok {
		return StreamStats{}, false
	}

	stream.mu.RLock()
	defer stream.mu.RUnlock()

	return StreamStats{
		ID:           stream.ID,
		Seq:          atomic.LoadUint32(&stream.Seq),
		State:        stream.State,
		BytesIn:      atomic.LoadUint64(&stream.BytesIn),
		BytesOut:     atomic.LoadUint64(&stream.BytesOut),
		PacketsIn:    atomic.LoadUint64(&stream.PacketsIn),
		PacketsOut:   atomic.LoadUint64(&stream.PacketsOut),
		LastActivity: atomic.LoadInt64(&stream.LastActivity),
		Created:      stream.Created,
		Closed:       stream.Closed,
	}, true
}

type StreamStats struct {
	ID           uint16
	Seq          uint32
	State        StreamState
	BytesIn      uint64
	BytesOut     uint64
	PacketsIn    uint64
	PacketsOut   uint64
	LastActivity int64
	Created      int64
	Closed       bool
}

func (s *Stream) IncrementSeq() uint32 {
	return atomic.AddUint32(&s.Seq, 1)
}

func (s *Stream) GetSeq() uint32 {
	return atomic.LoadUint32(&s.Seq)
}

func (s *Stream) AddBytesIn(bytes uint64) {
	atomic.AddUint64(&s.BytesIn, bytes)
	atomic.AddUint64(&s.PacketsIn, 1)
	atomic.StoreInt64(&s.LastActivity, getCurrentTime())
}

func (s *Stream) AddBytesOut(bytes uint64) {
	atomic.AddUint64(&s.BytesOut, bytes)
	atomic.AddUint64(&s.PacketsOut, 1)
	atomic.StoreInt64(&s.LastActivity, getCurrentTime())
}

func (s *Stream) UpdateRemoteWindow(delta uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.RemoteWindow += delta
}

func (s *Stream) ConsumeRemoteWindow(size uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.RemoteWindow < size {
		return false
	}
	s.RemoteWindow -= size
	return true
}

func (s *Stream) GetRemoteWindow() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.RemoteWindow
}

func (s *Stream) UpdateLocalWindow(delta uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LocalWindow += delta
}

func (s *Stream) ConsumeLocalWindow(size uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.LocalWindow >= size {
		s.LocalWindow -= size
	} else {
		s.LocalWindow = 0
	}
}

func getCurrentTime() int64 {
	timeCache := util.GetGlobalTimeCache()
	return timeCache.Now().Unix()
}

type StreamPacket struct {
	StreamID  uint16
	Seq       uint32
	Payload   []byte
	Control   bool
	NoEncrypt bool
}

func PackStreams(packets []StreamPacket) *headers.BatchPacket {
	batch := &headers.BatchPacket{
		Packets: make([]headers.BatchItem, 0, len(packets)),
	}

	for _, pkt := range packets {
		batch.Packets = append(batch.Packets, headers.BatchItem{
			StreamID:  pkt.StreamID,
			Seq:       pkt.Seq,
			Payload:   pkt.Payload,
			Control:   pkt.Control,
			NoEncrypt: pkt.NoEncrypt,
		})
	}

	return batch
}
