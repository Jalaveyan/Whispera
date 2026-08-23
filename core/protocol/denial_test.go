package protocol

import (
	"bytes"
	"strings"
	"testing"
)

func TestDenialRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	const msg = "IP limit exceeded; you will have to wait until someone disconnects."
	WriteDenial(&buf, msg)

	got, ok := ParseDenial(buf.Bytes())
	if !ok {
		t.Fatal("a written denial must parse back")
	}
	if got != msg {
		t.Fatalf("got %q, want %q", got, msg)
	}
}

func TestDenialTruncatesLongMessage(t *testing.T) {
	var buf bytes.Buffer
	WriteDenial(&buf, strings.Repeat("x", denialMaxLen*2))

	got, ok := ParseDenial(buf.Bytes())
	if !ok {
		t.Fatal("a truncated denial must still parse")
	}
	if len(got) != denialMaxLen {
		t.Fatalf("message is %d bytes, want %d", len(got), denialMaxLen)
	}
}

func TestDenialIgnoresTunnelData(t *testing.T) {
	cases := map[string][]byte{
		"empty":         {},
		"tls record":    {0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x02},
		"tls app data":  {0x17, 0x03, 0x03, 0x01, 0x00},
		"short":         {0xFF, 'W', 'D'},
		"magic no body": {0xFF, 'W', 'D', 'N', 0x00, 0x10},
		"wrong magic":   {0xFF, 'W', 'D', 'X', 0x00, 0x01, 'a'},
		"high bytes":    bytes.Repeat([]byte{0xFF}, 32),
	}
	for name, b := range cases {
		if msg, ok := ParseDenial(b); ok {
			t.Errorf("%s: parsed as denial %q", name, msg)
		}
	}
}
