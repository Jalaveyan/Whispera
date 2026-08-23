package tunnel

import (
	"context"
	"net"
	"time"

	"github.com/nekoskin/whispera/core/protocol"
)

type TunnelState int

const (
	StateDisconnected TunnelState = iota
	StateConnecting
	StateConnected

	StateReconnecting
	StateRotating
	StateError
)

func (s TunnelState) String() string {
	switch s {
	case StateDisconnected:
		return "disconnected"
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	case StateReconnecting:
		return "reconnecting"
	case StateRotating:
		return "rotating"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

type WhisperaOptions struct {
	EnableWhispera   bool
	WhisperaAddr     string
	WhisperaSNI      string
	WhisperaSecret   []byte
	WhisperaCertPin  string
	WhisperaIDPub    string
	WhisperaSelPub   string
	WhisperaQUICAddr string
	WhisperaMux      int

	EnableGRPC     bool
	GRPCAddr       string
	GRPCServerName string
	GRPCUseTLS     bool

	EnableYaDisk     bool
	YaDiskOAuthToken string
	YaDiskSessionID  string
}

type decoyActivity interface {
	Enter()
	Leave()
}

type Config struct {
	HandshakeStrategy    *protocol.HandshakeStrategy
	ServerAddr           string
	Transport            string
	PSK                  []byte
	TransportWhitelist   []string
	TransportBlacklist   []string
	KeepaliveInterval    time.Duration
	ReconnectInterval    time.Duration
	ReconnectMaxDelay    time.Duration
	MaxReconnectAttempts int
	DecoyGate            decoyActivity
	ConnectionTimeout    time.Duration
	KillSwitchEnabled    bool
	KillSwitchAllowLAN   bool
	KillSwitchAllowDNS   bool

	EnableASNBypass bool
	DomainFrontHost string

	WhisperaOptions

	BehavioralProfile string

	TransportConfig map[string]interface{}

	ForceObfuscation bool

	CustomDialFn func(ctx context.Context) (net.Conn, error)

	CustomSNI   string
	NoSNI       bool
	RateLimitKB int

	EnableIPSpoof  bool
	SpoofSourceIPs []string

	TLSFragmentSize int

	ForceSNI string
}

func DefaultConfig() *Config {
	return &Config{
		KeepaliveInterval:    15 * time.Second,
		ReconnectInterval:    2 * time.Second,
		ReconnectMaxDelay:    30 * time.Second,
		MaxReconnectAttempts: 0,
		ConnectionTimeout:    90 * time.Second,
		ForceObfuscation:     true,
	}
}

func (c *Config) Validate() error {
	if c.KeepaliveInterval <= 0 {
		c.KeepaliveInterval = 10 * time.Second
	}
	if c.ReconnectInterval <= 0 {
		c.ReconnectInterval = 2 * time.Second
	}
	if c.ReconnectMaxDelay <= 0 {
		c.ReconnectMaxDelay = 30 * time.Second
	}
	if c.ConnectionTimeout <= 0 {
		c.ConnectionTimeout = 90 * time.Second
	}
	return nil
}
