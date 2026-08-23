package relay

import (
	"net"
	"testing"
	"time"
)

type panicConn struct{ net.Conn }

func (panicConn) Read([]byte) (int, error) {
	panic("сбой в апстрим-копировании")
}
func (panicConn) Write(b []byte) (int, error) { return len(b), nil }
func (panicConn) Close() error                { return nil }

func TestUpstreamPanicStillReportsResult(t *testing.T) {
	s, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	resCh := make(chan copyResult, 2)
	s.relayTCP(panicConn{}, b, resCh)

	done := make(chan struct{})
	go func() {
		_, _, _, _ = collectCopyResults(resCh)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("collectCopyResults завис: апстрим не отчитался после паники")
	}
}
