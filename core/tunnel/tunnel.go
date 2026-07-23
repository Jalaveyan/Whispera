package tunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/nekoskin/whispera/common/log"
	"github.com/nekoskin/whispera/common/runtime/base"
	"github.com/nekoskin/whispera/common/runtime/events"
	"github.com/nekoskin/whispera/common/runtime/interfaces"
	asnbypass "github.com/nekoskin/whispera/core/asn_bypass"
	"github.com/nekoskin/whispera/core/killswitch"
	"github.com/nekoskin/whispera/core/protocol"
	"github.com/nekoskin/whispera/neural"
	"io"
	"net"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	xmux "github.com/sagernet/sing-mux"
	singlog "github.com/sagernet/sing/common/logger"
	singM "github.com/sagernet/sing/common/metadata"
)

var log = logger.Module("tunnel")

var _ interfaces.Module = (*Manager)(nil)

func safeGo(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error("PANIC in %s: %v\n%s", name, r, debug.Stack())
			}
		}()
		fn()
	}()
}

const (
	ModuleName    = "tunnel.manager"
	ModuleVersion = "1.0.0"

	FrameHeaderSize  = 8
	FrameTypeConnect = 0x01
	FrameTypeData    = 0x04
	FrameTypeClose   = 0x05
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

type MLOptions struct {
	MLServerURL     string
	MLTLSSkipVerify bool
	MLToken         string
	SNIModelDir     string
	SNIDomainsURL   string
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
	DisableNeural        bool
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
	ResidentialProxies []string
	EnableJA3Randomize bool

	WhisperaOptions
	MLOptions

	BehavioralProfile string

	ServerList []string

	Regions         map[string][]string
	PreferredRegion string

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

type Manager struct {
	*base.Module
	config *Config

	sm *tunnelStateMachine
	cb *circuitBreaker

	smClient *xmux.Client
	smMu     sync.Mutex

	connMu    sync.RWMutex
	sessionID uint32

	tunDevice interfaces.TUNDevice
	handshake interfaces.HandshakeHandler
	dataPlane interfaces.DataPlane
	crypto    interfaces.CryptoProvider

	currentSNI string

	reconnectAttempts uint32
	reconnecting      int32
	bytesUp           uint64
	bytesDown         uint64
	lastKeepalive     int64
	lastPong          int64
	connectedAt       time.Time

	reconnectDone chan struct{}

	onStateChange func(TunnelState)

	killSwitch killSwitchController

	obfuscator        interfaces.Obfuscator
	asnBypassDialer   tcpBypassDialer
	isTransportSecure bool

	rtLane *rtLaneManager
	ml     *mlOrchestrator

	boFailCount     int32
	boLastSuccessAt int64
	boLastErrType   int32
	tlsErrStreak    int32

	goroutineLimiter *base.GoroutineLimiter

	connCfg connConfig

	lastGoodMu         sync.RWMutex
	lastGoodSNI        string
	lastGoodTransport  string
	lastGoodServerAddr string

	qualityRTTEWMA int64
	missedKAs      int32
}

func New(cfg *Config) (*Manager, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	var forceObfs int32 = 1
	if !cfg.ForceObfuscation {
		forceObfs = 0
	}

	m := &Manager{
		Module:           base.NewModule(ModuleName, ModuleVersion, []string{"handshake.handler"}),
		config:           cfg,
		goroutineLimiter: base.NewGoroutineLimiter(1024),
		reconnectDone:    make(chan struct{}),
	}
	m.connCfg.forceObfuscation.Store(forceObfs)
	m.rtLane = newRTLaneManager(m)
	m.cb = newCircuitBreaker()
	m.sm = newTunnelStateMachine(m.onStateTransition)
	close(m.reconnectDone)

	if cfg.EnableASNBypass || cfg.ForceSNI != "" {
		frontDomain := cfg.DomainFrontHost
		enableSNIMask := false

		if cfg.ForceSNI != "" {
			frontDomain = cfg.ForceSNI
			enableSNIMask = true
		}

		asnConfig := &asnbypass.Config{
			Strategy:               cfg.ASNBypassStrategy,
			TLSFingerprint:         cfg.TLSFingerprint,
			FrontDomain:            frontDomain,
			EnableSNIMask:          enableSNIMask,
			ResidentialProxies:     cfg.ResidentialProxies,
			EnableJA3Randomization: cfg.EnableJA3Randomize,
			EnableTLSFragmentation: true,
			TLSFragmentSize: func() int {
				if cfg.TLSFragmentSize > 0 {
					return cfg.TLSFragmentSize
				}
				return 40
			}(),
			ConnectionBurstLimit: 5,
			ConnectionCooldown:   2 * time.Second,
			FailoverTimeout:      cfg.ConnectionTimeout,
			FallbackStrategies:   []asnbypass.Strategy{asnbypass.StrategyTLSMasquerade, asnbypass.StrategyDomainFronting},
		}

		m.asnBypassDialer = asnbypass.NewDialer(asnConfig)
	}

	if cfg.KillSwitchEnabled {
		ksConfig := &killswitch.Config{
			Enabled:      cfg.KillSwitchEnabled,
			AllowLAN:     cfg.KillSwitchAllowLAN,
			AllowDNS:     cfg.KillSwitchAllowDNS,
			PersistRules: false,
		}

		if ks, err := killswitch.New(ksConfig); err == nil {
			m.killSwitch = ks
			ks.OnStateChange(func(state killswitch.State) {
				m.PublishEvent("killswitch.state_changed", map[string]interface{}{
					"state": state.String(),
				})
			})
		}
	}

	m.ml = newMLOrchestrator(m)

	if cfg.CustomSNI != "" {
		if cfg.TransportConfig == nil {
			cfg.TransportConfig = make(map[string]interface{})
		}
		if _, exists := cfg.TransportConfig["sni"]; !exists {
			cfg.TransportConfig["sni"] = cfg.CustomSNI
		}
	}

	if cfg.RateLimitKB > 0 {
		m.connCfg.SetRateLimitKB(cfg.RateLimitKB)
	}

	if cfg.EnableIPSpoof && len(cfg.SpoofSourceIPs) > 0 {
		m.connCfg.SetSpoofIPs(cfg.SpoofSourceIPs)
	}

	return m, nil
}

func (m *Manager) Start() error {
	if err := m.Module.Start(); err != nil {
		return err
	}
	m.SetHealthy(true, "tunnel manager running")
	m.PublishEvent(events.EventTypeModuleStarted, nil)

	safeGo("Reconnect", func() { m.Reconnect(m.Context()) })

	return nil
}

func (m *Manager) Stop() error {
	m.Disconnect()
	m.PublishEvent(events.EventTypeModuleStopped, nil)
	return m.Module.Stop()
}

func (m *Manager) PreWarm() {
	safeGo("PreWarm", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		_ = m.Connect(ctx)
	})
}

func (m *Manager) SetDependencies(
	tun interfaces.TUNDevice,
	handshake interfaces.HandshakeHandler,
	dataPlane interfaces.DataPlane,
	crypto interfaces.CryptoProvider,
) {
	m.tunDevice = tun
	m.handshake = handshake
	m.dataPlane = dataPlane
	m.crypto = crypto
}

func (m *Manager) Connect(ctx context.Context) error {
	if _, blocked := m.sm.CompareAndSet(StateConnecting, StateConnecting, StateConnected); blocked {
		return nil
	}

	m.Disconnect()

	if len(m.config.ServerList) > 0 {
		if best := m.pickServer(ctx); best != "" {
			m.config.ServerAddrTCP = best
			m.config.ServerAddr = best
		}
	}

	return m.connectInternal(ctx, false)
}

func (m *Manager) connectInternal(ctx context.Context, isRotation bool) error {
	if !isRotation {
		m.setState(StateConnecting)
	} else {
		m.setState(StateRotating)
	}

	if streamMuxEnabled() {
		return m.connectStreamMux(ctx)
	}
	return m.connectPerFlow(ctx)
}

func (m *Manager) Disconnect() {
	m.smMu.Lock()
	if m.smClient != nil {
		m.smClient.Close()
		m.smClient = nil
	}
	m.smMu.Unlock()

	if m.killSwitch != nil {
		m.killSwitch.Disable()
	}

	m.setState(StateDisconnected)
	m.PublishEvent("tunnel.disconnected", nil)
}

func (m *Manager) waitForOngoingReconnect(ctx context.Context) error {
	m.connMu.RLock()
	done := m.reconnectDone
	m.connMu.RUnlock()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func (m *Manager) applyTSPUCountermeasure(err error, dialLatency float64) {
	if m.ml.tspuDetector == nil {
		return
	}
	dialDur := time.Duration(dialLatency) * time.Millisecond
	if strings.Contains(err.Error(), "reset") {
		m.ml.tspuDetector.RecordRST(m.currentSNI, dialDur)
	}
	dpiType, conf := m.ml.tspuDetector.DetectTSPU()
	if dpiType == neural.DPITypeNone || conf < 0.65 {
		return
	}
	if cm := neural.TSPUCountermeasure(dpiType); cm != "" && cm != m.config.Transport {
		m.config.Transport = cm
	}
}

func (m *Manager) Reconnect(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if !atomic.CompareAndSwapInt32(&m.reconnecting, 0, 1) {
		return m.waitForOngoingReconnect(ctx)
	}

	newDone := make(chan struct{})
	m.connMu.Lock()
	m.reconnectDone = newDone
	m.connMu.Unlock()

	originalTransport := m.config.Transport
	transportFallbackActivated := false
	defer func() {
		if transportFallbackActivated {
			m.config.Transport = originalTransport
		}
		close(newDone)
		atomic.StoreInt32(&m.reconnecting, 0)
	}()

	if !m.circuitBreakerAllow() {
		return fmt.Errorf("circuit breaker open")
	}

	m.setState(StateReconnecting)
	delay := m.config.ReconnectInterval
	attempts := 0

	const fallbackAfterAttempts = 3

	m.lastGoodMu.RLock()
	zeroRTTSNI := m.lastGoodSNI
	zeroRTTTransport := m.lastGoodTransport
	m.lastGoodMu.RUnlock()

	for {
		attempts++
		atomic.StoreUint32(&m.reconnectAttempts, uint32(attempts))

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if m.config.MaxReconnectAttempts > 0 && attempts > m.config.MaxReconnectAttempts {
			err := fmt.Errorf("max reconnect attempts exceeded")
			m.circuitBreakerFail()
			m.setError(err)
			return err
		}

		if attempts == fallbackAfterAttempts+1 &&
			originalTransport != "" && originalTransport != "auto" &&
			!transportFallbackActivated {
			transportFallbackActivated = true
			m.config.Transport = "auto"
		}

		m.Disconnect()

		m.connMu.Lock()
		if attempts == 1 && zeroRTTSNI != "" {
			m.currentSNI = zeroRTTSNI
			if zeroRTTTransport != "" {
				m.config.Transport = zeroRTTTransport
			}
		} else {
			m.currentSNI = ""
		}
		m.connMu.Unlock()

		dialStart := time.Now()
		var err error
		if attempts == 1 && zeroRTTSNI != "" {
			err = m.connectInternal(ctx, false)
		} else {
			err = m.Connect(ctx)
		}
		dialLatency := float64(time.Since(dialStart).Milliseconds())
		if err == nil {
			atomic.StoreInt32(&m.boFailCount, 0)
			atomic.StoreInt64(&m.boLastSuccessAt, time.Now().Unix())
			m.circuitBreakerSuccess()
			return nil
		}

		m.applyTSPUCountermeasure(err, dialLatency)
		atomic.AddInt32(&m.boFailCount, 1)
		m.circuitBreakerFail()

		backoffDelay := delay
		delay = time.Duration(float64(delay) * 2)
		if delay > m.config.ReconnectMaxDelay {
			delay = m.config.ReconnectMaxDelay
		}
		if backoffDelay < delay {
			backoffDelay = delay
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoffDelay):
		}
	}
}

func (m *Manager) circuitBreakerAllow() bool { return m.cb.Allow() }
func (m *Manager) circuitBreakerFail()       { m.cb.Fail() }
func (m *Manager) circuitBreakerSuccess()    { m.cb.Success() }

func streamMuxEnabled() bool { return os.Getenv("WHISPERA_STREAM_MUX") == "1" }

type camoDialer struct{ m *Manager }

func (d camoDialer) DialContext(ctx context.Context, network string, dest singM.Socksaddr) (net.Conn, error) {
	dial := d.m.rtDial()
	if dial == nil {
		return nil, fmt.Errorf("stream-mux: no whispera dialer")
	}
	return dial(ctx)
}

func (d camoDialer) ListenPacket(ctx context.Context, dest singM.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("stream-mux: udp not supported")
}

func (m *Manager) getStreamMuxClient() (*xmux.Client, error) {
	m.smMu.Lock()
	defer m.smMu.Unlock()
	if m.smClient != nil {
		return m.smClient, nil
	}
	c, err := xmux.NewClient(xmux.Options{
		Dialer:   camoDialer{m},
		Logger:   singlog.NOP(),
		Protocol: "smux",
	})
	if err != nil {
		return nil, err
	}
	m.smClient = c
	return c, nil
}

type decoyLeaveConn struct {
	net.Conn
	m    *Manager
	once sync.Once
}

func (d *decoyLeaveConn) Close() error {
	d.once.Do(func() {
		if d.m.config.DecoyGate != nil {
			d.m.config.DecoyGate.Leave()
		}
	})
	return d.Conn.Close()
}

func (m *Manager) connectPerFlow(ctx context.Context) error {
	dial := m.rtDial()
	if dial == nil {
		err := fmt.Errorf("direct: no camo dialer")
		m.setError(err)
		return err
	}
	probe, err := dial(ctx)
	if err != nil {
		m.setError(err)
		return err
	}
	probe.Close()

	m.setState(StateConnected)
	m.connMu.Lock()
	m.connectedAt = time.Now()
	m.connMu.Unlock()
	return nil
}

func (m *Manager) openStreamPerFlow(ctx context.Context, proto byte, addr string, port uint16) (net.Conn, error) {
	dial := m.rtDial()
	if dial == nil {
		return nil, fmt.Errorf("direct: no camo dialer")
	}
	conn, err := dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("direct dial: %w", err)
	}

	wantSplice := proto&protocol.SpliceProtoBit != 0
	proto &^= protocol.SpliceProtoBit
	splice := wantSplice && protocol.SpliceEnabled()
	var raw net.Conn
	if splice {
		if raw = netConnOf(conn); raw == nil {
			splice = false
		}
	}
	hdrProto := proto
	if splice {
		hdrProto |= protocol.SpliceProtoBit
	}

	addrBytes := []byte(addr)
	header := make([]byte, 1+2+len(addrBytes)+2)
	header[0] = hdrProto
	binary.BigEndian.PutUint16(header[1:3], uint16(len(addrBytes)))
	copy(header[3:], addrBytes)
	binary.BigEndian.PutUint16(header[3+len(addrBytes):], port)
	if _, err := conn.Write(header); err != nil {
		conn.Close()
		return nil, fmt.Errorf("direct connect header: %w", err)
	}

	if m.config.DecoyGate != nil {
		m.config.DecoyGate.Enter()
	}
	dl := &decoyLeaveConn{Conn: conn, m: m}
	if splice {
		return &clientSpliceConn{decoyLeaveConn: dl, raw: raw, padLeft: spliceRecordsToPad}, nil
	}
	return dl, nil
}

func netConnOf(c net.Conn) net.Conn {
	if nc, ok := c.(interface{ NetConn() net.Conn }); ok {
		if raw := nc.NetConn(); raw != nil {
			return raw
		}
	}
	return nil
}

const spliceRecordsToPad = 8

type clientSpliceConn struct {
	*decoyLeaveConn
	raw     net.Conn
	padLeft int
	rbuf    []byte
}

func (c *clientSpliceConn) Write(b []byte) (int, error) { return c.Conn.Write(b) }

func (c *clientSpliceConn) Read(b []byte) (int, error) {
	if len(c.rbuf) > 0 {
		n := copy(b, c.rbuf)
		c.rbuf = c.rbuf[n:]
		return n, nil
	}
	if c.padLeft == 0 {
		return c.raw.Read(b)
	}
	var hdr [5]byte
	if _, err := io.ReadFull(c.raw, hdr[:]); err != nil {
		return 0, err
	}
	if hdr[0] != 0x17 {
		return 0, fmt.Errorf("splice: bad record type 0x%02x", hdr[0])
	}
	body := int(binary.BigEndian.Uint16(hdr[3:5]))
	rec := make([]byte, body)
	if _, err := io.ReadFull(c.raw, rec); err != nil {
		return 0, err
	}
	c.padLeft--
	if body < 2 {
		return 0, fmt.Errorf("splice: short record")
	}
	dataLen := int(binary.BigEndian.Uint16(rec[0:2]))
	if 2+dataLen > body {
		return 0, fmt.Errorf("splice: bad data len")
	}
	data := rec[2 : 2+dataLen]
	n := copy(b, data)
	if n < len(data) {
		c.rbuf = append(c.rbuf[:0], data[n:]...)
	}
	return n, nil
}

func (m *Manager) connectStreamMux(ctx context.Context) error {
	if _, err := m.getStreamMuxClient(); err != nil {
		m.setError(err)
		return err
	}
	dial := m.rtDial()
	if dial == nil {
		err := fmt.Errorf("stream-mux: no whispera dialer")
		m.setError(err)
		return err
	}
	probe, err := dial(ctx)
	if err != nil {
		m.setError(err)
		return err
	}
	probe.Close()

	m.setState(StateConnected)
	m.connMu.Lock()
	m.connectedAt = time.Now()
	m.connMu.Unlock()
	log.Warn("stream-mux mode active (h2mux) — yamux pool bypassed")
	return nil
}

func (m *Manager) openStreamMux(ctx context.Context, proto byte, addr string, port uint16) (net.Conn, error) {
	c, err := m.getStreamMuxClient()
	if err != nil {
		return nil, err
	}
	conn, err := c.DialContext(ctx, "tcp", singM.ParseSocksaddrHostPort(addr, port))
	if err != nil {
		return nil, fmt.Errorf("stream-mux dial: %w", err)
	}
	if _, err := conn.Write([]byte{proto}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("stream-mux proto write: %w", err)
	}
	if m.config.DecoyGate != nil {
		m.config.DecoyGate.Enter()
	}
	return &decoyLeaveConn{Conn: conn, m: m}, nil
}

func (m *Manager) OpenStream(ctx context.Context, proto byte, addr string, port uint16) (net.Conn, error) {
	if streamMuxEnabled() {
		return m.openStreamMux(ctx, proto, addr, port)
	}
	return m.openStreamPerFlow(ctx, proto, addr, port)
}

const (
	protoTCP = 0x06
	protoUDP = 0x11
)

func (m *Manager) rtDial() func(context.Context) (net.Conn, error) { return m.rtLane.dial() }

func (m *Manager) GetState() TunnelState { return m.sm.Get() }

func (m *Manager) LastError() error { return m.sm.LastError() }

func (m *Manager) IsConnected() bool { return m.sm.IsConnected() }

func (m *Manager) GetSessionID() uint32 { return m.sessionID }

func (m *Manager) OnStateChange(callback func(TunnelState)) { m.onStateChange = callback }

func (m *Manager) setState(state TunnelState) { m.sm.Set(state) }

func (m *Manager) setError(err error) {
	m.sm.SetError(err)
	m.SetHealthy(false, err.Error())
}

func (m *Manager) onStateTransition(old, new TunnelState) {
	if m.onStateChange != nil {
		m.onStateChange(new)
	}
	m.PublishEvent("tunnel.state_changed", map[string]interface{}{
		"old_state": old.String(),
		"new_state": new.String(),
	})
	if m.obfuscator != nil {
		type connActiveSet interface{ SetConnectionActive(bool) }
		if setter, ok := m.obfuscator.(connActiveSet); ok {
			setter.SetConnectionActive(new == StateConnected)
		}
	}
}

func (m *Manager) DialStream(ctx context.Context, network, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("dial stream: invalid addr %q: %w", addr, err)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port == 0 {
		return nil, fmt.Errorf("dial stream: invalid port in %q", addr)
	}

	proto := byte(protoTCP)
	if network == "udp" {
		proto = protoUDP
	}

	return m.OpenStream(ctx, proto, host, port)
}
