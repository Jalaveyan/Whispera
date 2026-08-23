package interfaces

import (
	"context"
	"net"
	"time"
)

type Module interface {
	Name() string
	Version() string
	Dependencies() []string
	Init(ctx context.Context, cfg ModuleConfig) error
	Start() error
	Stop() error
	HealthCheck() HealthStatus
}

type ModuleConfig interface {
	Validate() error
}

type HealthStatus struct {
	Healthy     bool
	Message     string
	LastChecked time.Time
	Details     map[string]interface{}
}

type Direction string

const (
	DirectionInbound  Direction = "inbound"
	DirectionOutbound Direction = "outbound"
)

type TransportType string

const (
	TransportUDP    TransportType = "udp"
	TransportTCP    TransportType = "tcp"
	TransportQUIC   TransportType = "quic"
	TransportYaDisk TransportType = "yadisk"
)

type Transport interface {
	Module
	Dial(ctx context.Context, addr string) (net.Conn, error)
	Type() TransportType
	Close() error
}

type Packet struct {
	SessionID uint32
	StreamID  uint16
	Seq       uint32
	Flags     byte
	Payload   []byte
	SrcAddr   net.Addr
	DstAddr   net.Addr
	Timestamp time.Time
}

type Destination struct {
	Type    DestinationType
	Address string
	Port    uint16
	Tag     string
}

type DestinationType string

const (
	DestinationDirect DestinationType = "direct"
	DestinationProxy  DestinationType = "proxy"
	DestinationBlock  DestinationType = "block"
	DestinationTUN    DestinationType = "tun"
)

type Router interface {
	Module
	Route(ctx context.Context, packet *Packet) (*Destination, error)
	AddRule(rule RoutingRule) error
	RemoveRule(id string) error
	UpdateRules(rules []RoutingRule) error
	GetRules() []RoutingRule
}

type RoutingRule struct {
	ID          string
	Priority    int
	Conditions  []RuleCondition
	Destination Destination
	Metadata    map[string]interface{}
}

type RuleCondition struct {
	Field    string
	Operator string
	Value    interface{}
}

type ObfuscationProcessor interface {
	Process(data []byte, direction Direction) ([]byte, time.Duration, error)
}

type ObfuscationControl interface {
	SetProfile(name string) error
	GetProfile() string
	SetThreatLevel(level int)
	SetRealityKey(key string)
}

type Obfuscator interface {
	Module
	ObfuscationProcessor
	ObfuscationControl
	GetStats() ObfuscationStats
}

type ObfuscationStats struct {
	PacketsProcessed uint64
	BytesProcessed   uint64
	AvgProcessTime   time.Duration
	ProfileName      string
	ThreatLevel      int
}
