package tunnel

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nekoskin/whispera/core/protocol"

	logger "github.com/nekoskin/whispera/common/log"
	"github.com/nekoskin/whispera/common/runtime/base"
	"github.com/nekoskin/whispera/common/runtime/events"
	"github.com/nekoskin/whispera/common/runtime/interfaces"
	asnbypass "github.com/nekoskin/whispera/core/asn_bypass"
	"github.com/nekoskin/whispera/core/killswitch"

	xmux "github.com/sagernet/sing-mux"
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

	selector *selector

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
	m.selector = newSelector(m)
	m.cb = newCircuitBreaker()
	m.sm = newTunnelStateMachine(m.onStateTransition)
	close(m.reconnectDone)

	if cfg.EnableASNBypass || cfg.ForceSNI != "" {
		asnConfig := &asnbypass.Config{
			Strategy:               cfg.ASNBypassStrategy,
			TLSFingerprint:         cfg.TLSFingerprint,
			EnableJA3Randomization: cfg.EnableJA3Randomize,
			// Splitting the ClientHello across ~13 records of 20-60 bytes, each
			// a millisecond or four apart, defeats a filter that looks for the
			// SNI in the first packet — the name never lands in one segment.
			// It is also unmistakable: no browser sends a hello that way, and it
			// shows on the first connection without any statistics. Which of the
			// two matters depends on what is inspecting the link, so it is a
			// setting rather than a default, and WHISPERA_HELLO_FRAG=0 turns it
			// off for a link where shape is what gets watched.
			EnableTLSFragmentation: os.Getenv("WHISPERA_HELLO_FRAG") != "0",
			TLSFragmentSize: func() int {
				if cfg.TLSFragmentSize > 0 {
					return cfg.TLSFragmentSize
				}
				return 40
			}(),
			ConnectionBurstLimit: 5,
			ConnectionCooldown:   2 * time.Second,
			FailoverTimeout:      cfg.ConnectionTimeout,
			FallbackStrategies:   []asnbypass.Strategy{asnbypass.StrategyTLSMasquerade, asnbypass.StrategyCloudflareBypass},
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
	crypto interfaces.CryptoProvider,
) {
	m.tunDevice = tun
	m.handshake = handshake
	m.crypto = crypto
}

func (m *Manager) Connect(ctx context.Context) error {
	if _, blocked := m.sm.CompareAndSet(StateConnecting, StateConnecting, StateConnected); blocked {
		return nil
	}

	m.Disconnect()

	return m.connectInternal(ctx, false)
}

func (m *Manager) connectInternal(ctx context.Context, isRotation bool) error {
	if !isRotation {
		m.setState(StateConnecting)
	} else {
		m.setState(StateRotating)
	}

	if protocol.StreamMuxEnabled() {
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

		var err error
		if attempts == 1 && zeroRTTSNI != "" {
			err = m.connectInternal(ctx, false)
		} else {
			err = m.Connect(ctx)
		}
		if err == nil {
			atomic.StoreInt32(&m.boFailCount, 0)
			atomic.StoreInt64(&m.boLastSuccessAt, time.Now().Unix())
			m.circuitBreakerSuccess()
			return nil
		}

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
