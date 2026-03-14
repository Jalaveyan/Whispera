package marionette

import (
	"testing"
)

func TestFrameMarshalUnmarshal(t *testing.T) {
	frame := &ChatFrame{
		Type:      FrameMessage,
		SeqNum:    42,
		Timestamp: 1710000000,
		ChatID:    12345,
		Payload:   []byte("hello world"),
	}

	data := frame.Marshal()
	if len(data) != 16+len(frame.Payload) {
		t.Errorf("expected %d bytes, got %d", 16+len(frame.Payload), len(data))
	}

	parsed, err := UnmarshalFrame(data)
	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if parsed.Type != FrameMessage {
		t.Errorf("expected FrameMessage, got %d", parsed.Type)
	}
	if parsed.SeqNum != 42 {
		t.Errorf("expected seq 42, got %d", parsed.SeqNum)
	}
	if parsed.ChatID != 12345 {
		t.Errorf("expected chatID 12345, got %d", parsed.ChatID)
	}
	if string(parsed.Payload) != "hello world" {
		t.Errorf("expected 'hello world', got %q", string(parsed.Payload))
	}
}

func TestUnmarshalFrameTooShort(t *testing.T) {
	_, err := UnmarshalFrame([]byte{0x01, 0x02})
	if err == nil {
		t.Error("expected error for short frame")
	}
}

func TestProtocolEngineWrapUnwrap(t *testing.T) {
	pe := NewProtocolEngine(1, 0)
	defer pe.Stop()

	original := []byte("tunnel data payload")
	wrapped := pe.WrapData(original)

	unwrapped, err := pe.UnwrapData(wrapped)
	if err != nil {
		t.Fatalf("unwrap error: %v", err)
	}
	if string(unwrapped) != string(original) {
		t.Errorf("expected %q, got %q", string(original), string(unwrapped))
	}
}

func TestProtocolEngineCoverFrames(t *testing.T) {
	pe := NewProtocolEngine(100, 0)
	defer pe.Stop()

	coverTypes := []FrameType{
		FrameKeepAlive, FramePresence, FrameTypingStart,
		FrameTypingStop, FrameReadReceipt, FrameBackgroundSync,
	}

	for _, ft := range coverTypes {
		pe.sendCoverFrame(ft)
	}

	stats := pe.Stats()
	if stats["cover_sent"] != 6 {
		t.Errorf("expected 6 cover frames, got %d", stats["cover_sent"])
	}
}

func TestProtocolEngineTypingSequence(t *testing.T) {
	pe := NewProtocolEngine(1, 0)
	defer pe.Stop()

	frames := pe.GenerateTypingSequence()
	if len(frames) < 3 {
		t.Errorf("expected at least 3 frames in typing sequence, got %d", len(frames))
	}

	first, _ := UnmarshalFrame(frames[0])
	if first.Type != FrameTypingStart {
		t.Errorf("first frame should be TypingStart, got %d", first.Type)
	}

	last, _ := UnmarshalFrame(frames[len(frames)-1])
	if last.Type != FrameTypingStop {
		t.Errorf("last frame should be TypingStop, got %d", last.Type)
	}
}

func TestProtocolEngineMessageExchange(t *testing.T) {
	pe := NewProtocolEngine(1, 0)
	defer pe.Stop()

	data := []byte("test message data")
	frames := pe.GenerateMessageExchange(data)

	if len(frames) < 5 {
		t.Errorf("expected at least 5 frames in message exchange, got %d", len(frames))
	}

	var hasMessage, hasAck bool
	for _, f := range frames {
		cf, err := UnmarshalFrame(f)
		if err != nil {
			continue
		}
		if cf.Type == FrameMessage {
			hasMessage = true
			if string(cf.Payload) != string(data) {
				t.Errorf("message payload mismatch")
			}
		}
		if cf.Type == FrameMessageAck {
			hasAck = true
		}
	}

	if !hasMessage {
		t.Error("missing message frame")
	}
	if !hasAck {
		t.Error("missing ack frame")
	}
}

func TestProtocolEngineStats(t *testing.T) {
	pe := NewProtocolEngine(1, 0)
	defer pe.Stop()

	pe.WrapData([]byte("test"))
	pe.WrapData([]byte("test2"))
	pe.sendCoverFrame(FrameKeepAlive)

	stats := pe.Stats()
	if stats["data_sent"] != 2 {
		t.Errorf("expected 2 data sent, got %d", stats["data_sent"])
	}
	if stats["cover_sent"] != 1 {
		t.Errorf("expected 1 cover sent, got %d", stats["cover_sent"])
	}
	if stats["frames_sent"] != 3 {
		t.Errorf("expected 3 total frames, got %d", stats["frames_sent"])
	}
}
