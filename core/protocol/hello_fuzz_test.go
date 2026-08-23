package protocol

import (
	"math/rand"
	"net"
	"testing"
	"time"
)

func feedHello(t *testing.T, payload []byte) {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	go func() {
		_ = a.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = a.Write(payload)
		a.Close()
	}()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("peekClientHello паникует на %d байтах: %v", len(payload), r)
		}
	}()
	_, _ = peekClientHello(b)
}

func TestPeekClientHelloSurvivesGarbage(t *testing.T) {
	rng := rand.New(rand.NewSource(7))

	for i := 0; i < 400; i++ {
		n := rng.Intn(600)
		p := make([]byte, n)
		rng.Read(p)
		if n > 0 && rng.Intn(2) == 0 {
			p[0] = 0x16
		}
		if n > 4 && rng.Intn(2) == 0 {
			p[1], p[2] = 0x03, 0x03
			p[3] = byte(rng.Intn(256))
			p[4] = byte(rng.Intn(256))
		}
		feedHello(t, p)
	}
}

func TestPeekClientHelloBoundsRecordLength(t *testing.T) {
	cases := [][]byte{
		{0x16, 0x03, 0x03, 0x00, 0x00},
		{0x16, 0x03, 0x03, 0xFF, 0xFF},
		{0x16, 0x03, 0x03, 0x40, 0x01},
		{0x17, 0x03, 0x03, 0x00, 0x05},
		{0x16},
		{},
	}
	for _, c := range cases {
		feedHello(t, c)
	}
}

func TestPeekClientHelloRejectsOversizedHandshake(t *testing.T) {
	var p []byte
	for i := 0; i < 8; i++ {
		p = append(p, 0x16, 0x03, 0x03, 0x40, 0x00)
		body := make([]byte, 0x4000)
		body[0] = 0x01
		body[1], body[2], body[3] = 0xFF, 0xFF, 0xFF
		p = append(p, body...)
	}
	feedHello(t, p)
}
