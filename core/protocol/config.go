package protocol

import (
	"context"
	"net"
	"time"

	quicgo "github.com/quic-go/quic-go"
	utls "github.com/refraction-networking/utls"
)

type ClientConfig struct {
	ServerAddr    string
	ServerName    string
	ServerNames   []string
	SharedSecret  []byte
	ServerCertPin string
	ServerIDPub   string
	SessionCache  any
	TCPDialer     func(ctx context.Context, network, addr string) (net.Conn, error)

	EnableQUIC bool
	QUICAddr   string
	OnQUICConn func(*quicgo.Conn)

	HelloSplitOffset int
	HelloID          utls.ClientHelloID
	HelloRaw         []byte
	OnHandshake      func(result HandshakeResult, latency time.Duration)
	OnLiveReset      func()
	OnLiveOK         func()
}

type ServerConfig struct {
	ListenAddr       string
	ExtraListenAddrs []string
	BackendH2CAddr   string
	TLSCert          string
	TLSKey           string
	Domain           string
	ACMEDir          string
	DecoyOrigin      string
	DecoyCertDir     string
	AsymBiasRatio    float64
	SharedSecret     []byte

	QUICListenAddr       string
	ExtraQUICListenAddrs []string

	GetUsers func() []UserEntry
	OnConn   func(conn net.Conn, userID string, secret []byte)

	sessionRegistry
}

type sessionRegistry struct {
	proxy *decoyProxy

	seenTokens tokenSeenSet

	altSvcHeader string
}

const replayWindowSeconds = (2*authWindowTolerance + 1) * authWindowSeconds

func (r *sessionRegistry) consumeToken(token string) bool {
	return r.seenTokens.consume(token, time.Now().Unix())
}
