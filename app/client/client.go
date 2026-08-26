package client

import (
	"context"
	"flag"
	stdlog "log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	logger "github.com/nekoskin/whispera/common/log"
	"github.com/nekoskin/whispera/common/runtime/lifecycle"
	"github.com/nekoskin/whispera/core/config"
	"github.com/nekoskin/whispera/core/killswitch"
	"github.com/nekoskin/whispera/core/protocol"
	"github.com/nekoskin/whispera/core/protocol/fingerprint"
	"github.com/nekoskin/whispera/core/socks5"
	"github.com/nekoskin/whispera/core/tunnel"

	_ "go.uber.org/automaxprocs"
)

var log = logger.Module("client")

var Version = "2.0.0"

type clientRuntimeParams struct {
	serverAddress    string
	asnBypassEnabled bool
	whisperaSecret   []byte
	tunnelPSK        []byte
	transports       []string
}

var (
	configPath       = flag.String("config", "", "Path to configuration file")
	serverAddr       = flag.String("server", "", "Server address (host:port)")
	socksAddr        = flag.String("socks", "127.0.0.1:10800", "SOCKS5 listen address the external router connects to")
	connKey          = flag.String("key", "", "Connection key (whispera://...)")
	transport        = flag.String("transport", "tcp", "Transport mode: auto|tcp|udp")
	asnBypass        = flag.Bool("asn-bypass", false, "Enable ASN bypass for VPN/datacenter IP evasion")
	tlsFingerprint   = flag.String("tls-fingerprint", "chrome", "TLS fingerprint for ASN bypass: chrome, firefox, safari, ios, android")
	enableKillSwitch = flag.Bool("kill-switch", false, "Enable kill switch to prevent traffic leaks")
	allowLAN         = flag.Bool("allow-lan", true, "Allow LAN traffic when kill switch is enabled")
	userKey          = flag.String("user-key", "", "User private key (base64) for ML-mode auth — sets PSK without a full connection key")
	noInternalTun    = flag.Bool("no-tun", true, "Disable internal TUN (use external like Mihomo)")
	russianService   = flag.String("russian-service", "", "Enable Russian Service masquerading (e.g. vk_video)")
	controlPort      = flag.String("control-port", "10801", "Control server port (default 10801)")
	splitRulesJSON   = flag.String("split-rules", "", "Split tunnel rules as JSON, same format the host app uses")
	dnsUpstream      = flag.String("dns", "", "DNS upstream: host:port for UDP (8.8.8.8:53), https://... for DoH (https://1.1.1.1/dns-query). Empty = 1.1.1.1:53. 'system' = ISP resolver")
	spoofIPs         = flag.String("spoof-ips", "", "Comma-separated source IPs for IP spoofing (requires multiple local IPs)")
	adminTokenFlag   = flag.String("admin-token", "", "Admin token required for privileged control endpoints (e.g. /spoof). Empty = no auth")
	tlsFragSize      = flag.Int("tls-fragment", 0, "TLS ClientHello fragment size in bytes (0=default 40, range 16-200). Smaller = harder for DPI but more RTT")
	logFilePath      = flag.String("log-file", "", "Write logs to file (default: in-memory only, no disk storage)")
	forceSNIFlag     = flag.String("sni", "", "Force custom SNI in TLS ClientHello for all connections (e.g. www.google.com). Overrides asn-bypass SNI")
	subURL           = flag.String("sub-url", "", "Subscription URL for automatic key refresh (checked every 24h)")
	subInterval      = flag.Duration("sub-interval", 24*time.Hour, "Subscription refresh interval")
	bypassDNS        = flag.String("bypass-dns", "77.88.8.8:53", "DNS server used for bypass resolver (never goes through tunnel)")
	hwidFlag         = flag.Bool("hwid", true, "Send a persistent per-device ID in the handshake (false = random ID per connection)")
	forceFingerprint = flag.String("force-fingerprint", "", "Force a specific TLS fingerprint for the main tunnel handshake: chrome, chrome_120, chrome_115, firefox, firefox_120, safari, ios, android, edge. Empty = auto/random (default)")
)

func loadHandshakeSignal(ctx context.Context) (*protocol.HandshakeStrategy, func()) {
	strategy := protocol.NewHandshakeStrategy()
	path := handshakeSignalPath()
	if path == "" {
		return strategy, func() {}
	}

	save := func() {
		if err := strategy.Save(path); err != nil {
			stdlog.Printf("handshake signal save: %v", err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		stdlog.Printf("handshake signal dir: %v", err)
	}
	if err := strategy.Load(path); err != nil && !os.IsNotExist(err) {
		stdlog.Printf("handshake signal load: %v", err)
	}

	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				save()
			}
		}
	}()
	return strategy, save
}

type clientRuntime struct {
	cfg       *config.ClientConfig
	ctx       context.Context
	handshake *protocol.HandshakeStrategy
	params    *clientRuntimeParams
	spoofList []string
}

func (r *clientRuntime) tunnelCfg(transport, addr string, tc map[string]interface{}) *tunnel.Config {
	return &tunnel.Config{
		HandshakeStrategy: r.handshake,
		ServerAddr:        addr,
		Transport:         transport,
		PSK:               r.params.tunnelPSK,
		KeepaliveInterval: 30 * time.Second,
		EnableASNBypass:   r.params.asnBypassEnabled,
		WhisperaOptions:   whisperaOptions(r.cfg, r.params.whisperaSecret),
		TransportConfig:   tc,
		ForceSNI:          getGlobalSNI(),
	}
}

func (r *clientRuntime) newTunnel(transport string) *tunnel.Manager {
	c := r.tunnelCfg(transport, r.params.serverAddress, r.cfg.TransportConfig)
	c.TransportWhitelist = r.cfg.TransportWhitelist
	c.TransportBlacklist = r.cfg.TransportBlacklist
	m, _ := tunnel.New(c)
	return m
}

func (r *clientRuntime) entryCfg(e *TransportEntry) *tunnel.Config {
	e.mu.Lock()
	transport := e.Transport
	force := e.ForceObfuscation
	profile := e.BehavioralProfile
	customSNI := e.SNI
	noSNI := e.NoSNI
	rateLimitKB := e.RateLimitKB
	e.mu.Unlock()

	if customSNI == "" {
		customSNI = getGlobalSNI()
	}

	tc := r.cfg.TransportConfig
	if customSNI != "" && !noSNI {
		tc = make(map[string]interface{}, len(r.cfg.TransportConfig)+1)
		for k, v := range r.cfg.TransportConfig {
			tc[k] = v
		}
		tc["sni"] = customSNI
	}

	c := r.tunnelCfg(transport, r.params.serverAddress, tc)
	c.ForceObfuscation = force
	c.BehavioralProfile = profile
	c.CustomSNI = customSNI
	c.NoSNI = noSNI
	c.RateLimitKB = rateLimitKB
	c.EnableIPSpoof = len(r.spoofList) > 0
	c.SpoofSourceIPs = r.spoofList
	c.TLSFragmentSize = *tlsFragSize
	return c
}

func newPoolEntry(id, transport, server string, status connStatus, m *tunnel.Manager) *TransportEntry {
	return &TransportEntry{
		ID:               id,
		Transport:        transport,
		Server:           server,
		Enabled:          true,
		Obfuscated:       true,
		ForceObfuscation: true,
		Status:           status,
		mgr:              m,
	}
}

func (r *clientRuntime) addStandbyTransports() {
	for _, transport := range r.params.transports[1:] {
		m := r.newTunnel(transport)
		e := newPoolEntry(pool.NextID(), transport, r.params.serverAddress, connStatusStandby, m)
		pool.Add(e)
	}
}

func (r *clientRuntime) applySpoofIPs(primary *tunnel.Manager) {
	if *spoofIPs == "" {
		return
	}
	for _, ip := range strings.Split(*spoofIPs, ",") {
		if ip = strings.TrimSpace(ip); ip != "" {
			r.spoofList = append(r.spoofList, ip)
		}
	}
	if len(r.spoofList) == 0 {
		return
	}
	primary.SetSpoofIPs(r.spoofList)
	stdlog.Printf("IP spoofing enabled: %v", r.spoofList)
}

func (r *clientRuntime) connectBridge(bridgeCtx context.Context, router *socks5.MultiRouter, bridgeID, bridgeAddr string, rules []string) {
	m, err := tunnel.New(r.tunnelCfg(r.params.transports[0], bridgeAddr, r.cfg.TransportConfig))
	if err != nil {
		stdlog.Printf("[multi-bridge] build tunnel %s failed: %v", bridgeID, err)
		return
	}
	e := newPoolEntry(pool.NextID(), r.params.transports[0], bridgeAddr, connStatusConnecting, m)
	pool.Add(e)

	fail := func(stage string, err error, cancel context.CancelFunc) {
		stdlog.Printf("[multi-bridge] %s %s (%s) failed: %v", stage, bridgeID, bridgeAddr, err)
		e.mu.Lock()
		e.Status = connStatusFailed
		e.Error = err.Error()
		e.mu.Unlock()
		cancel()
	}

	connCtx, cancel := context.WithCancel(bridgeCtx)
	if err := m.Init(connCtx, nil); err != nil {
		fail("init", err, cancel)
		return
	}
	e.mu.Lock()
	e.cancel = cancel
	e.mu.Unlock()

	if err := m.Connect(connCtx); err != nil {
		fail("connect", err, cancel)
		return
	}
	e.mu.Lock()
	e.Status = connStatusConnected
	e.ConnectedAt = time.Now()
	e.mu.Unlock()

	stdlog.Printf("[multi-bridge] bridge %s connected (%s), rules: %v", bridgeID, bridgeAddr, rules)
	if err := router.AttachBridgeTunnel(bridgeID, m); err != nil {
		stdlog.Printf("[multi-bridge] bridge %s attach error: %v", bridgeID, err)
	}
}

func (r *clientRuntime) startSubscription() *config.SubscriptionManager {
	url := *subURL
	if url == "" && r.cfg != nil {
		url = r.cfg.SubscriptionURL
	}
	if url == "" && *connKey != "" {
		if ck, err := config.ParseConnectionKey(*connKey); err == nil {
			url = ck.SubscriptionURL
		}
	}
	if url == "" {
		return nil
	}

	stdlog.Printf("Subscription URL: %s (refresh every %s)", url, *subInterval)
	mgr := config.NewSubscriptionManager(url, *subInterval, func(keys []*config.ConnectionKey) {
		if len(keys) == 0 {
			return
		}
		best := keys[0]
		stdlog.Printf("Subscription updated: %d keys available, using %q (server=%s)", len(keys), best.Name, best.Server)
		if best.Server != "" && best.Server != r.params.serverAddress {
			r.params.serverAddress = best.Server
			stdlog.Printf("Subscription: server address updated to %s", r.params.serverAddress)
		}
	})
	mgr.Start()
	globalSubscriptionMgr = mgr
	return mgr
}

func newKillSwitch() *killswitch.KillSwitch {
	if !*enableKillSwitch {
		return nil
	}
	ks, err := killswitch.New(&killswitch.Config{
		Enabled:  true,
		AllowLAN: *allowLAN,
		AllowDNS: true,
	})
	if err != nil {
		stdlog.Printf("WARNING: Failed to create kill switch: %v", err)
		return nil
	}
	return ks
}

func armKillSwitch(ks *killswitch.KillSwitch, serverAddress string) {
	host, portStr, err := net.SplitHostPort(serverAddress)
	if err != nil {
		return
	}
	ip := net.ParseIP(host)
	if ks == nil || ip == nil {
		return
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return
	}
	ks.SetVPNServer(ip, port)
	if err := ks.Enable(); err != nil {
		stdlog.Printf("WARNING: Failed to enable kill switch: %v", err)
		return
	}
	stdlog.Printf("Kill Switch ENABLED - traffic blocked except to %s", host)
}

func (r *clientRuntime) connectPrimary(primary *TransportEntry, ks *killswitch.KillSwitch) {
	setStatus := func(status connStatus, err error) {
		primary.mu.Lock()
		primary.Status = status
		if err != nil {
			primary.Error = err.Error()
		} else {
			primary.ConnectedAt = time.Now()
		}
		primary.mu.Unlock()
	}

	if err := primary.mgr.Connect(r.ctx); err != nil {
		stdlog.Printf("WARNING: Failed to connect to proxy server: %v", err)
		setStatus(connStatusFailed, err)
		if !pool.AnyConnected() {
			stdlog.Printf("Tunnel down — fail-closed: non-bypass traffic refused until reconnect (no unencrypted fallback); retry on next stream")
		}
		return
	}

	setStatus(connStatusConnected, nil)
	stdlog.Printf("Connected to proxy server via %s", r.params.transports[0])

	if !*noInternalTun {
		if host, _, err := net.SplitHostPort(r.params.serverAddress); err == nil {
			stdlog.Printf("proxy server IP for routing: %s", host)
		}
		return
	}

	stdlog.Printf("External TUN mode: external router will handle TUN/routing")
	stdlog.Printf("SOCKS5 proxy ready at %s", *socksAddr)
	armKillSwitch(ks, r.params.serverAddress)
}

func newLifecycle() *lifecycle.Manager {
	mobileMu.Lock()
	lc := pkgLC
	mobileMu.Unlock()
	if lc != nil {
		return lc
	}
	return lifecycle.NewManager(lifecycle.Config{
		ShutdownTimeout: 30 * time.Second,
	})
}

func stopPool(socksMod *socks5.Module) {
	for _, e := range pool.List() {
		e.mu.Lock()
		mgr := e.mgr
		e.mu.Unlock()
		if mgr != nil {
			mgr.Stop()
		}
	}
	socksMod.Stop()
}

func waitForShutdown(ctx context.Context) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sigChan:
	case <-ctx.Done():
	}
}

func RunMain() {
	if !mobileMode {
		debug.SetGCPercent(100)
		debug.SetMemoryLimit(200 << 20)
		flag.Parse()
	}
	if *forceFingerprint != "" {
		fingerprint.SetForced(*forceFingerprint)
	}

	setupLogging()
	cfg := loadClientConfig()

	lc := newLifecycle()
	ctx := lc.Context()

	logDeviceID()
	handshakeSignal, stopHandshakeSignal := loadHandshakeSignal(ctx)
	defer stopHandshakeSignal()

	socksMod, dnsMod, stm := setupNetworking(cfg)
	defer stopPool(socksMod)

	r := &clientRuntime{
		cfg:       cfg,
		ctx:       ctx,
		handshake: handshakeSignal,
		params:    resolveRuntimeParams(cfg),
	}
	if r.params.asnBypassEnabled {
		stdlog.Printf("ASN bypass enabled: ClientHello fragmentation")
	}

	tunnels := newTunnelPool(
		func(e *TransportEntry, c *tunnel.Config) bool {
			return restartTransportEntry(ctx, e, c)
		},
		r.entryCfg,
	)
	multiRouter := socks5.NewMultiRouter(tunnels)
	globalMultiRouter = multiRouter
	socksMod.SetTunnel(multiRouter)
	if err := socksMod.Start(); err != nil {
		fatalf("Failed to start SOCKS5: %v", err)
	}

	primary := newPoolEntry(pool.NextID(), r.params.transports[0], r.params.serverAddress,
		connStatusConnecting, r.newTunnel(r.params.transports[0]))
	pool.Add(primary)
	r.addStandbyTransports()

	controlAddr = "127.0.0.1:" + *controlPort
	adminToken = *adminTokenFlag
	globalDNS = dnsMod
	r.applySpoofIPs(primary.mgr)

	reconnectEntry = func(e *TransportEntry) {
		restartTransportEntry(ctx, e, r.entryCfg(e))
	}
	newMultiBridgeTunnel = func(bridgeCtx context.Context, bridgeID, bridgeAddr string, rules []string) {
		r.connectBridge(bridgeCtx, multiRouter, bridgeID, bridgeAddr, rules)
	}

	if subMgr := r.startSubscription(); subMgr != nil {
		defer subMgr.Stop()
	}

	startControlServer(ctx)
	if err := lc.Start(); err != nil {
		fatalf("Failed to start: %v", err)
	}

	stdlog.Printf("Connecting to VPN server: %s via %s", r.params.serverAddress, r.params.transports[0])
	r.connectPrimary(primary, newKillSwitch())

	dnsMod.SetDialContext(tunnels.DialStream)
	stdlog.Printf("DNS now routed through tunnel")
	startGeoIPRefresh(ctx, stm, dnsMod, tunnels.DialStream)
	stdlog.Printf("SOCKS5 proxy listening on %s", *socksAddr)

	waitForShutdown(ctx)
}
