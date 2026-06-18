package protocol

import (
	"context"
	"net"
	"sync"
	"time"
)

type ClientConfig struct {
	ServerAddr    string
	ServerName    string
	ServerNames   []string
	SharedSecret  []byte
	ServerCertPin string
	SessionCache  any
	TCPDialer     func(ctx context.Context, network, addr string) (net.Conn, error)

	EnableQUIC bool
	QUICAddr   string
}

type ServerConfig struct {
	ListenAddr       string
	ExtraListenAddrs []string
	TLSCert          string
	TLSKey           string
	Domain           string
	ACMEDir          string
	DecoyOrigin      string
	AsymBiasRatio    float64
	SharedSecret     []byte

	QUICListenAddr string

	GetUsers  func() []UserEntry
	OnConn    func(conn net.Conn, userID string)
	GANDecide GANDecideFunc

	proxy       *decoyProxy
	sessions    sync.Map
	sessionMu   sync.Mutex
	sessionCond *sync.Cond

	seenTokens tokenSeenSet

	altSvcHeader string
}

const replayWindowSeconds = (2*authWindowTolerance + 1) * authWindowSeconds

func (cfg *ServerConfig) consumeToken(token string) bool {
	return cfg.seenTokens.consume(token, time.Now().Unix())
}

func (cfg *ServerConfig) initCond() {
	if cfg.sessionCond == nil {
		cfg.sessionCond = sync.NewCond(&cfg.sessionMu)
	}
}

func (cfg *ServerConfig) storeSession(key string, sess *restSession) {
	cfg.sessions.Store(key, sess)
	cfg.sessionCond.Broadcast()
}

func (cfg *ServerConfig) waitSession(key string, timeout time.Duration) (*restSession, bool) {
	deadline := time.Now().Add(timeout)
	cfg.sessionMu.Lock()
	defer cfg.sessionMu.Unlock()
	var wakeTimer *time.Timer
	defer func() {
		if wakeTimer != nil {
			wakeTimer.Stop()
		}
	}()
	for {
		if v, ok := cfg.sessions.Load(key); ok {
			return v.(*restSession), true
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, false
		}
		if wakeTimer == nil {
			wakeTimer = time.AfterFunc(remaining, cfg.sessionCond.Broadcast)
		}
		cfg.sessionCond.Wait()
	}
}
