package tunnel

import (
	"context"
	"net"
	"time"

	asnbypass "github.com/nekoskin/whispera/core/asn_bypass"
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
	ServerAddr           string
	ServerAddrTCP        string
	Transport            string
	PSK                  []byte
	TransportWhitelist   []string
	TransportBlacklist   []string
	KeepaliveInterval    time.Duration
	ReconnectInterval    time.Duration
	ReconnectMaxDelay    time.Duration
	MaxReconnectAttempts int
	DisableAutoReconnect bool
	DecoyGate            decoyActivity
	ConnectionTimeout    time.Duration
	EnableRotation       bool
	RotationInterval     time.Duration
	DrainingTimeout      time.Duration
	KillSwitchEnabled    bool
	KillSwitchAllowLAN   bool
	KillSwitchAllowDNS   bool

	EnableASNBypass    bool
	ASNBypassStrategy  asnbypass.Strategy
	TLSFingerprint     string
	DomainFrontHost    string
	EnableJA3Randomize bool

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

	QualityMissedKeepalives int

	PaddingMaxSize int
}

func DefaultConfig() *Config {
	return &Config{
		KeepaliveInterval:    15 * time.Second,
		ReconnectInterval:    2 * time.Second,
		ReconnectMaxDelay:    30 * time.Second,
		MaxReconnectAttempts: 0,
		ConnectionTimeout:    90 * time.Second,
		EnableRotation:       true,
		RotationInterval:     60 * time.Minute,
		DrainingTimeout:      90 * time.Minute,
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
	if c.RotationInterval < 1*time.Minute {
		c.RotationInterval = 15 * time.Minute
	}
	if c.DrainingTimeout < c.RotationInterval {
		c.DrainingTimeout = c.RotationInterval * 2
	}
	return nil
}
