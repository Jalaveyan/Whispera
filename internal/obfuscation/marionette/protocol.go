package marionette

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type FrameType byte

const (
	FrameTypingStart    FrameType = 0x01
	FrameTypingStop     FrameType = 0x02
	FrameMessage        FrameType = 0x03
	FrameMessageAck     FrameType = 0x04
	FrameReadReceipt    FrameType = 0x05
	FramePresence       FrameType = 0x06
	FrameMediaUpload    FrameType = 0x07
	FrameMediaChunk     FrameType = 0x08
	FrameVoiceChunk     FrameType = 0x09
	FrameStickerSend    FrameType = 0x0A
	FrameFeedRequest    FrameType = 0x0B
	FrameFeedResponse   FrameType = 0x0C
	FramePushNotify     FrameType = 0x0D
	FrameBackgroundSync FrameType = 0x0E
	FrameKeepAlive      FrameType = 0x0F
	FrameData           FrameType = 0x10
)

type ChatFrame struct {
	Type      FrameType
	SeqNum    uint32
	Timestamp int64
	ChatID    uint32
	Payload   []byte
}

func (f *ChatFrame) Marshal() []byte {
	payloadLen := len(f.Payload)
	frame := make([]byte, 16+payloadLen)

	frame[0] = byte(f.Type)
	frame[1] = 0x01
	binary.BigEndian.PutUint16(frame[2:4], uint16(payloadLen))
	binary.BigEndian.PutUint32(frame[4:8], f.SeqNum)
	binary.BigEndian.PutUint32(frame[8:12], uint32(f.Timestamp))
	binary.BigEndian.PutUint32(frame[12:16], f.ChatID)

	copy(frame[16:], f.Payload)
	return frame
}

func UnmarshalFrame(data []byte) (*ChatFrame, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("frame too short: %d", len(data))
	}

	payloadLen := int(binary.BigEndian.Uint16(data[2:4]))
	if len(data) < 16+payloadLen {
		return nil, fmt.Errorf("incomplete frame: need %d, have %d", 16+payloadLen, len(data))
	}

	return &ChatFrame{
		Type:      FrameType(data[0]),
		SeqNum:    binary.BigEndian.Uint32(data[4:8]),
		Timestamp: int64(binary.BigEndian.Uint32(data[8:12])),
		ChatID:    binary.BigEndian.Uint32(data[12:16]),
		Payload:   data[16 : 16+payloadLen],
	}, nil
}

type ProtocolEngine struct {
	mu       sync.Mutex
	seqNum   uint32
	chatID   uint32
	stopCh   chan struct{}

	coverInterval time.Duration
	sendFn        func([]byte) error

	stats struct {
		framesSent     uint64
		framesReceived uint64
		coverSent      uint64
		dataSent       uint64
	}
}

func NewProtocolEngine(chatID uint32, coverInterval time.Duration) *ProtocolEngine {
	if coverInterval <= 0 {
		coverInterval = 3 * time.Second
	}
	return &ProtocolEngine{
		chatID:        chatID,
		coverInterval: coverInterval,
		stopCh:        make(chan struct{}),
	}
}

func (pe *ProtocolEngine) SetSendFunc(fn func([]byte) error) {
	pe.sendFn = fn
}

func (pe *ProtocolEngine) nextSeq() uint32 {
	return atomic.AddUint32(&pe.seqNum, 1)
}

func (pe *ProtocolEngine) WrapData(data []byte) []byte {
	frame := &ChatFrame{
		Type:      FrameData,
		SeqNum:    pe.nextSeq(),
		Timestamp: time.Now().Unix(),
		ChatID:    pe.chatID,
		Payload:   data,
	}
	atomic.AddUint64(&pe.stats.dataSent, 1)
	atomic.AddUint64(&pe.stats.framesSent, 1)
	return frame.Marshal()
}

func (pe *ProtocolEngine) UnwrapData(frame []byte) ([]byte, error) {
	cf, err := UnmarshalFrame(frame)
	if err != nil {
		return nil, err
	}
	atomic.AddUint64(&pe.stats.framesReceived, 1)

	switch cf.Type {
	case FrameData:
		return cf.Payload, nil
	case FrameKeepAlive, FrameTypingStart, FrameTypingStop,
		FramePresence, FrameReadReceipt, FrameBackgroundSync:
		return nil, nil
	default:
		return cf.Payload, nil
	}
}

func (pe *ProtocolEngine) StartCoverTraffic() {
	go pe.coverLoop()
}

func (pe *ProtocolEngine) Stop() {
	close(pe.stopCh)
}

func (pe *ProtocolEngine) coverLoop() {
	ticker := time.NewTicker(pe.coverInterval)
	defer ticker.Stop()

	patterns := []FrameType{
		FrameKeepAlive, FramePresence, FrameTypingStart,
		FrameTypingStop, FrameReadReceipt, FrameBackgroundSync,
	}

	for {
		select {
		case <-pe.stopCh:
			return
		case <-ticker.C:
			idx := randByte() % byte(len(patterns))
			pe.sendCoverFrame(patterns[idx])
		}
	}
}

func (pe *ProtocolEngine) sendCoverFrame(ft FrameType) {
	var payload []byte

	switch ft {
	case FrameKeepAlive:
		payload = nil
	case FramePresence:
		payload = marshalJSON(map[string]interface{}{
			"status":    "online",
			"last_seen": time.Now().Unix(),
		})
	case FrameTypingStart:
		payload = marshalJSON(map[string]interface{}{
			"chat_id": pe.chatID,
			"action":  "typing",
		})
	case FrameTypingStop:
		payload = marshalJSON(map[string]interface{}{
			"chat_id": pe.chatID,
		})
	case FrameReadReceipt:
		payload = marshalJSON(map[string]interface{}{
			"chat_id": pe.chatID,
			"msg_id":  pe.seqNum,
		})
	case FrameBackgroundSync:
		payload = marshalJSON(map[string]interface{}{
			"sync_id":   pe.nextSeq(),
			"timestamp": time.Now().Unix(),
		})
	default:
	}

	frame := &ChatFrame{
		Type:      ft,
		SeqNum:    pe.nextSeq(),
		Timestamp: time.Now().Unix(),
		ChatID:    pe.chatID,
		Payload:   payload,
	}

	atomic.AddUint64(&pe.stats.coverSent, 1)
	atomic.AddUint64(&pe.stats.framesSent, 1)

	if pe.sendFn != nil {
		pe.sendFn(frame.Marshal())
	}
}

func (pe *ProtocolEngine) GenerateTypingSequence() [][]byte {
	var frames [][]byte

	start := &ChatFrame{
		Type:      FrameTypingStart,
		SeqNum:    pe.nextSeq(),
		Timestamp: time.Now().Unix(),
		ChatID:    pe.chatID,
		Payload:   marshalJSON(map[string]interface{}{"action": "typing"}),
	}
	frames = append(frames, start.Marshal())

	indicators := 2 + int(randByte())%4
	for i := 0; i < indicators; i++ {
		indicator := &ChatFrame{
			Type:      FrameTypingStart,
			SeqNum:    pe.nextSeq(),
			Timestamp: time.Now().Unix(),
			ChatID:    pe.chatID,
			Payload:   marshalJSON(map[string]interface{}{"action": "typing", "seq": i}),
		}
		frames = append(frames, indicator.Marshal())
	}

	stop := &ChatFrame{
		Type:      FrameTypingStop,
		SeqNum:    pe.nextSeq(),
		Timestamp: time.Now().Unix(),
		ChatID:    pe.chatID,
	}
	frames = append(frames, stop.Marshal())

	return frames
}

func (pe *ProtocolEngine) GenerateMessageExchange(data []byte) [][]byte {
	var frames [][]byte

	typingFrames := pe.GenerateTypingSequence()
	frames = append(frames, typingFrames...)

	msg := &ChatFrame{
		Type:      FrameMessage,
		SeqNum:    pe.nextSeq(),
		Timestamp: time.Now().Unix(),
		ChatID:    pe.chatID,
		Payload:   data,
	}
	frames = append(frames, msg.Marshal())

	ack := &ChatFrame{
		Type:      FrameMessageAck,
		SeqNum:    pe.nextSeq(),
		Timestamp: time.Now().Unix(),
		ChatID:    pe.chatID,
		Payload:   marshalJSON(map[string]interface{}{"msg_id": msg.SeqNum, "status": "delivered"}),
	}
	frames = append(frames, ack.Marshal())

	return frames
}

func (pe *ProtocolEngine) Stats() map[string]uint64 {
	return map[string]uint64{
		"frames_sent":     atomic.LoadUint64(&pe.stats.framesSent),
		"frames_received": atomic.LoadUint64(&pe.stats.framesReceived),
		"cover_sent":      atomic.LoadUint64(&pe.stats.coverSent),
		"data_sent":       atomic.LoadUint64(&pe.stats.dataSent),
	}
}

func marshalJSON(v interface{}) []byte {
	data, _ := json.Marshal(v)
	return data
}

func randByte() byte {
	b := make([]byte, 1)
	rand.Read(b)
	return b[0]
}
