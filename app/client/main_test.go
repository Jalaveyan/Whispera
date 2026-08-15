package client

import (
	"errors"
	"net"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/nekoskin/whispera/core/config"
)

func TestPickServerAddressTCP(t *testing.T) {
	cfg := &config.ClientConfig{ServerTCP: "tcp.example.com", Server: "fallback.example.com"}
	if got := pickServerAddress(cfg, "tcp"); got != "tcp.example.com" {
		t.Errorf("pickServerAddress() = %q, want %q", got, "tcp.example.com")
	}
}

func TestPickServerAddressTLSUsesTCP(t *testing.T) {
	cfg := &config.ClientConfig{ServerTCP: "tcp.example.com"}
	if got := pickServerAddress(cfg, "tls"); got != "tcp.example.com" {
		t.Errorf("pickServerAddress() = %q, want %q", got, "tcp.example.com")
	}
}

func TestPickServerAddressWSFallsBackToTCP(t *testing.T) {
	cfg := &config.ClientConfig{ServerTCP: "tcp.example.com"}
	if got := pickServerAddress(cfg, "ws"); got != "tcp.example.com" {
		t.Errorf("pickServerAddress() = %q, want %q", got, "tcp.example.com")
	}
}

func TestPickServerAddressWSPrefersServerWS(t *testing.T) {
	cfg := &config.ClientConfig{ServerWS: "ws.example.com", ServerTCP: "tcp.example.com"}
	if got := pickServerAddress(cfg, "ws"); got != "ws.example.com" {
		t.Errorf("pickServerAddress() = %q, want %q", got, "ws.example.com")
	}
}

func TestPickServerAddressUnknownTransportFallsBackToServer(t *testing.T) {
	cfg := &config.ClientConfig{Server: "fallback.example.com", ServerTCP: "tcp.example.com"}
	if got := pickServerAddress(cfg, "quic"); got != "fallback.example.com" {
		t.Errorf("pickServerAddress() = %q, want %q", got, "fallback.example.com")
	}
}

func TestLoadClientConfigUsesServerAddrFlag(t *testing.T) {
	origServer, origKey, origPath := *serverAddr, *connKey, *configPath
	defer func() {
		*serverAddr, *connKey, *configPath = origServer, origKey, origPath
	}()

	*connKey = ""
	*configPath = ""
	*serverAddr = "203.0.113.10:443"

	cfg := loadClientConfig()
	if cfg.Server != "203.0.113.10:443" {
		t.Errorf("loadClientConfig().Server = %q, want %q", cfg.Server, "203.0.113.10:443")
	}
}

func TestRevivePacedAfterSuccess(t *testing.T) {
	p := &tunnelPool{}
	done, mine := p.beginRevive()
	if !mine {
		t.Fatal("first revive must be allowed")
	}
	p.endRevive(done, true, true)
	if _, mine := p.beginRevive(); mine {
		t.Fatal("a successful restart must still hold off the next one: every failing stream would otherwise restart the tunnel again")
	}
}

func TestReviveBacksOffAfterFailure(t *testing.T) {
	p := &tunnelPool{}
	done, _ := p.beginRevive()
	p.endRevive(done, false, true)
	if _, mine := p.beginRevive(); mine {
		t.Fatal("revive must back off after a failed restart")
	}
	if p.fails != 1 {
		t.Fatalf("fails = %d, want 1", p.fails)
	}
}

func TestReviveNoOpDoesNotCountAsFailure(t *testing.T) {
	p := &tunnelPool{}
	done, _ := p.beginRevive()
	p.endRevive(done, false, false)
	if p.fails != 0 {
		t.Fatalf("fails = %d: a restart nobody attempted must not inflate the backoff", p.fails)
	}
	if _, mine := p.beginRevive(); !mine {
		t.Fatal("a no-op must not hold off the next real attempt")
	}
}

func TestConcurrentReviveWaitsForTheOneInFlight(t *testing.T) {
	p := &tunnelPool{}
	done, mine := p.beginRevive()
	if !mine {
		t.Fatal("first caller must own the attempt")
	}

	second, mine := p.beginRevive()
	if mine {
		t.Fatal("a second caller must not start its own restart")
	}
	if second != done {
		t.Fatal("the second caller must wait on the attempt already running, not fail immediately")
	}

	waited := make(chan struct{})
	go func() {
		<-second
		close(waited)
	}()
	p.endRevive(done, true, true)

	select {
	case <-waited:
	case <-time.After(time.Second):
		t.Fatal("waiting callers must be released when the attempt finishes")
	}
}

func TestNetworkDown(t *testing.T) {
	if !networkDown(&net.OpError{Op: "dial", Err: syscall.ENETUNREACH}) {
		t.Fatal("ENETUNREACH must be treated as a dead network, not as a dead tunnel")
	}
	if networkDown(errors.New("whispera: utls handshake: EOF")) {
		t.Fatal("a handshake failure must still trigger revive")
	}
}

func TestLogFileReusedAcrossRestarts(t *testing.T) {
	currentLogMu.Lock()
	saved := currentLog
	currentLog = nil
	currentLogMu.Unlock()
	defer func() {
		currentLogMu.Lock()
		if currentLog != nil {
			currentLog.f.Close()
		}
		currentLog = saved
		currentLogMu.Unlock()
	}()

	path := filepath.Join(t.TempDir(), "go-client.log")
	first, err := openTrimmingLog(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := openTrimmingLog(path)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("every reconnect calls setupLogging again — a second handle would leak a descriptor and a trimming goroutine")
	}
}
