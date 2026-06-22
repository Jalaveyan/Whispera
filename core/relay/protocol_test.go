package relay

import (
	"bytes"
	"testing"
)

func TestFrameEncodeDecodeRoundTrip(t *testing.T) {
	f := &Frame{
		StreamID: 42,
		Type:     FrameData,
		Flags:    FlagAck,
		Payload:  []byte("hello world"),
	}

	encoded, err := f.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.StreamID != f.StreamID || decoded.Type != f.Type || decoded.Flags != f.Flags {
		t.Fatalf("decoded header mismatch: got %+v, want %+v", decoded, f)
	}
	if !bytes.Equal(decoded.Payload, f.Payload) {
		t.Fatalf("decoded payload mismatch: got %q, want %q", decoded.Payload, f.Payload)
	}
}

func TestFrameEncodeTooLarge(t *testing.T) {
	f := &Frame{Payload: make([]byte, MaxPayloadLen+1)}
	if _, err := f.Encode(); err != ErrFrameTooLarge {
		t.Fatalf("expected ErrFrameTooLarge, got %v", err)
	}
}

func TestDecodeRejectsShortHeader(t *testing.T) {
	if _, err := Decode(make([]byte, HeaderSize-1)); err != ErrInvalidFrame {
		t.Fatalf("expected ErrInvalidFrame, got %v", err)
	}
}

func TestDecodeRejectsOversizedPayloadLen(t *testing.T) {
	hdr := make([]byte, HeaderSize)
	hdr[4] = 0xFF
	hdr[5] = 0xFF
	hdr[6] = 0xFF
	hdr[7] = 0xFF
	if _, err := Decode(hdr); err != ErrFrameTooLarge {
		t.Fatalf("expected ErrFrameTooLarge, got %v", err)
	}
}

func TestDecodeRejectsTruncatedPayload(t *testing.T) {
	hdr := make([]byte, HeaderSize)
	hdr[7] = 10
	if _, err := Decode(hdr); err != ErrInvalidFrame {
		t.Fatalf("expected ErrInvalidFrame for truncated payload, got %v", err)
	}
}

func TestConnectPayloadIPv4RoundTrip(t *testing.T) {
	p := &ConnectPayload{
		Profile:  ProfileBalanced,
		Protocol: ProtoTCP,
		AddrType: AddrTypeIPv4,
		Addr:     "192.168.1.42",
		Port:     8443,
	}

	decoded, err := DecodeConnectPayload(p.Encode())
	if err != nil {
		t.Fatalf("DecodeConnectPayload failed: %v", err)
	}
	if decoded.Addr != p.Addr || decoded.Port != p.Port || decoded.AddrType != p.AddrType {
		t.Fatalf("roundtrip mismatch: got %+v, want %+v", decoded, p)
	}
}

func TestConnectPayloadDomainRoundTrip(t *testing.T) {
	p := &ConnectPayload{
		Protocol: ProtoTCP,
		AddrType: AddrTypeDomain,
		Addr:     "example.com",
		Port:     443,
	}

	decoded, err := DecodeConnectPayload(p.Encode())
	if err != nil {
		t.Fatalf("DecodeConnectPayload failed: %v", err)
	}
	if decoded.Addr != p.Addr || decoded.Port != p.Port {
		t.Fatalf("roundtrip mismatch: got %+v, want %+v", decoded, p)
	}
}

func TestDecodeConnectPayloadRejectsTooShort(t *testing.T) {
	if _, err := DecodeConnectPayload([]byte{0x00, 0x01}); err != ErrInvalidFrame {
		t.Fatalf("expected ErrInvalidFrame, got %v", err)
	}
}

func TestDecodeConnectPayloadRejectsTruncatedIPv4(t *testing.T) {
	data := []byte{0x00, ProtoTCP, AddrTypeIPv4, 1, 2, 3}
	if _, err := DecodeConnectPayload(data); err != ErrInvalidFrame {
		t.Fatalf("expected ErrInvalidFrame for truncated IPv4, got %v", err)
	}
}

func TestDecodeConnectPayloadRejectsTruncatedDomainLen(t *testing.T) {
	data := []byte{0x00, ProtoTCP, AddrTypeDomain, 50}
	if _, err := DecodeConnectPayload(data); err != ErrInvalidFrame {
		t.Fatalf("expected ErrInvalidFrame for domain length exceeding buffer, got %v", err)
	}
}

func TestDecodeConnectPayloadRejectsUnknownAddrType(t *testing.T) {
	data := []byte{0x00, ProtoTCP, 0xEE, 0x00, 0x00}
	if _, err := DecodeConnectPayload(data); err != ErrInvalidFrame {
		t.Fatalf("expected ErrInvalidFrame for unknown addr type, got %v", err)
	}
}

func TestStreamIDGeneratorNeverReturnsZero(t *testing.T) {
	g := NewStreamIDGenerator()
	for i := 0; i < 1000; i++ {
		if id := g.Next(); id == 0 {
			t.Fatalf("Next() returned 0 at iteration %d", i)
		}
	}
}
