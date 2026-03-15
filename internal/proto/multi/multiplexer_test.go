package multi

import (
	"testing"
)

func TestStreamFlowControl(t *testing.T) {
	mux := NewStreamMultiplexer()
	stream, _ := mux.GetOrCreateStream(10)

	if stream.RemoteWindow != DefaultWindowSize {
		t.Errorf("expected RemoteWindow %d, got %d", DefaultWindowSize, stream.RemoteWindow)
	}

	consumed := stream.ConsumeRemoteWindow(1000)
	if !consumed {
		t.Error("expected to consume 1000 bytes")
	}
	if stream.RemoteWindow != DefaultWindowSize-1000 {
		t.Errorf("expected RemoteWindow %d, got %d", DefaultWindowSize-1000, stream.RemoteWindow)
	}

	consumed = stream.ConsumeRemoteWindow(DefaultWindowSize)
	if consumed {
		t.Error("expected NOT to consume more than window")
	}

	stream.UpdateRemoteWindow(500)
	if stream.RemoteWindow != DefaultWindowSize-1000+500 {
		t.Errorf("expected RemoteWindow %d, got %d", DefaultWindowSize-1000+500, stream.RemoteWindow)
	}
}

func TestStreamCloseCodes(t *testing.T) {
	mux := NewStreamMultiplexer()
	streamID := uint16(20)
	_, _ = mux.GetOrCreateStream(streamID)

	code := ErrCodeProtocolError
	payload := EncodeStreamClose(code)

	decoded := DecodeStreamClose(payload)
	if decoded != code {
		t.Errorf("expected code %d, got %d", code, decoded)
	}

	mux.CloseStream(streamID)
	if _, exists := mux.GetStream(streamID); exists {
		t.Error("expected stream to be removed")
	}
}

func TestHalfCloseLifecycle(t *testing.T) {
	mux := NewStreamMultiplexer()
	streamID := uint16(30)
	stream, _ := mux.GetOrCreateStream(streamID)

	mux.HalfCloseStream(streamID)
	if stream.State != StreamStateHalfClosed {
		t.Errorf("expected state HalfClosed, got %d", stream.State)
	}

	removed := mux.CleanupInactive(-1)
	if removed != 1 {
		t.Errorf("expected 1 stream removed, got %d", removed)
	}
}
