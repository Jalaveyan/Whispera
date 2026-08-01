package client

import (
	"context"
	"flag"
	stdlog "log"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
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
	serverAddress        string
	fallbackTCP          string
	asnBypassEnabled     bool
	asnBypassFingerprint string
	whisperaSecret       []byte
	tunnelPSK            []byte
	transports           []string
}

var (
	configPath       = flag.String("config", "", "Path to configuration file")
	serverAddr       = flag.String("server", "", "Server address (host:port)")
	socksAddr        = flag.String("socks", "127.0.0.1:10800", "SOCKS5 listen address for hev-socks5-tunnel")
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

	mobileMu.Lock()
	lc := pkgLC
	mobileMu.Unlock()
	if lc == nil {
		lc = lifecycle.NewManager(lifecycle.Config{
			ShutdownTimeout: 30 * time.Second,
			GracefulStop:    true,
		})
	}

	ctx := lc.Context()

	hsMod, cryptoMod := setupCoreModules()

	socksMod, dnsMod := setupNetworking(cfg)
	defer func() {
		for _, e := range pool.List() {
			e.mu.Lock()
			mgr := e.mgr
			e.mu.Unlock()
			if mgr != nil {
				mgr.Stop()
			}
		}
		socksMod.Stop()
	}()

	rp := resolveRuntimeParams(cfg)
	serverAddress := rp.serverAddress
	fallbackTCP := rp.fallbackTCP
	asnBypassEnabled := rp.asnBypassEnabled
	asnBypassFingerprint := rp.asnBypassFingerprint
	whisperaSecret := rp.whisperaSecret
	tunnelPSK := rp.tunnelPSK
	transports := rp.transports

	decoyGate := protocol.NewDecoyGate()
	if len(whisperaSecret) == 32 {
		decoyAddr := cfg.WhisperaAddr
		if decoyAddr == "" {
			decoyAddr = serverAddress
		}
		protocol.StartDecoy(ctx, decoyGate, &protocol.ClientConfig{
			ServerAddr:    decoyAddr,
			ServerName:    cfg.WhisperaSNI,
			SharedSecret:  whisperaSecret,
			ServerCertPin: cfg.WhisperaCertPin,
			ServerIDPub:   cfg.WhisperaIDPub,
			SessionCache:  protocol.SharedSessionCache(),
		})
	}

	newTunnelMod := func(tr string) *tunnel.Manager {
		m, _ := tunnel.New(&tunnel.Config{
			ServerAddr:              serverAddress,
			ServerAddrTCP:           fallbackTCP,
			Transport:               tr,
			PSK:                     tunnelPSK,
			TransportWhitelist:      cfg.TransportWhitelist,
			TransportBlacklist:      cfg.TransportBlacklist,
			KeepaliveInterval:       30 * time.Second,
			QualityMissedKeepalives: 3,
			DisableAutoReconnect:    true,
			DecoyGate:               decoyGate,
			EnableASNBypass:         asnBypassEnabled,
			TLSFingerprint:          asnBypassFingerprint,
			EnableJA3Randomize:      true,
			WhisperaOptions:         whisperaOptions(cfg, whisperaSecret),
			TransportConfig:         cfg.TransportConfig,
			ForceSNI:                getGlobalSNI(),
		})
		return m
	}

	var spoofList []string

	buildBaseCfg := func(e *TransportEntry) *tunnel.Config {
		e.mu.Lock()
		tr := e.Transport
		force := e.ForceObfuscation
		profile := e.BehavioralProfile
		customSNI := e.SNI
		noSNI := e.NoSNI
		rateLimitKB := e.RateLimitKB
		e.mu.Unlock()

		if customSNI == "" {
			customSNI = getGlobalSNI()
		}

		tc := cfg.TransportConfig
		if customSNI != "" && !noSNI {
			tc = make(map[string]interface{})
			for k, v := range cfg.TransportConfig {
				tc[k] = v
			}
			tc["sni"] = customSNI
		}

		return &tunnel.Config{
			ServerAddr:              serverAddress,
			ServerAddrTCP:           fallbackTCP,
			Transport:               tr,
			PSK:                     tunnelPSK,
			KeepaliveInterval:       30 * time.Second,
			QualityMissedKeepalives: 3,
			DisableAutoReconnect:    true,
			DecoyGate:               decoyGate,
			EnableASNBypass:         asnBypassEnabled,
			TLSFingerprint:          asnBypassFingerprint,
			EnableJA3Randomize:      true,
			WhisperaOptions:         whisperaOptions(cfg, whisperaSecret),
			TransportConfig:         tc,
			ForceObfuscation:        force,
			BehavioralProfile:       profile,
			CustomSNI:               customSNI,
			ForceSNI:                getGlobalSNI(),
			NoSNI:                   noSNI,
			RateLimitKB:             rateLimitKB,
			EnableIPSpoof:           len(spoofList) > 0,
			SpoofSourceIPs:          spoofList,
			TLSFragmentSize:         *tlsFragSize,
		}
	}

	restartEntry := func(e *TransportEntry, tunnelCfg *tunnel.Config) {
		restartTransportEntry(ctx, e, tunnelCfg, hsMod, cryptoMod)
	}

	if asnBypassEnabled {
		stdlog.Printf("ASN bypass enabled (fingerprint: %s)", asnBypassFingerprint)
	}

	tunnelMod := newTunnelMod(transports[0])
	tunnelMod.SetDependencies(nil, hsMod, cryptoMod)

	multiRouter := socks5.NewMultiRouter(tunnelMod)
	globalMultiRouter = multiRouter
	socksMod.SetTunnel(multiRouter)
	if err := socksMod.Start(); err != nil {
		fatalf("Failed to start SOCKS5: %v", err)
	}

	primaryEntry := &TransportEntry{
		ID:               pool.NextID(),
		Transport:        transports[0],
		Server:           serverAddress,
		Enabled:          true,
		Obfuscated:       true,
		ForceObfuscation: true,
		Status:           connStatusConnecting,
		mgr:              tunnelMod,
	}
	pool.Add(primaryEntry)

	extraTunnels := make([]*tunnel.Manager, 0, len(transports)-1)
	for i := 1; i < len(transports); i++ {
		tr := transports[i]
		m := newTunnelMod(tr)
		m.SetDependencies(nil, hsMod, cryptoMod)

		_, connCancel := context.WithCancel(ctx)
		entry := &TransportEntry{
			ID:               pool.NextID(),
			Transport:        tr,
			Server:           serverAddress,
			Enabled:          true,
			Obfuscated:       true,
			ForceObfuscation: true,
			Status:           connStatusStandby,
			mgr:              m,
			cancel:           connCancel,
		}
		pool.Add(entry)
		extraTunnels = append(extraTunnels, m)
	}

	controlAddr = "127.0.0.1:" + *controlPort
	adminToken = *adminTokenFlag
	globalDNS = dnsMod

	if *spoofIPs != "" {
		for _, ip := range strings.Split(*spoofIPs, ",") {
			if ip = strings.TrimSpace(ip); ip != "" {
				spoofList = append(spoofList, ip)
			}
		}
	}
	if len(spoofList) > 0 {
		tunnelMod.SetSpoofIPs(spoofList)
		stdlog.Printf("IP spoofing enabled: %v", spoofList)
	}

	reconnectEntry = func(e *TransportEntry) {
		restartEntry(e, buildBaseCfg(e))
	}

	newMultiBridgeTunnel = func(bridgeCtx context.Context, bridgeID, bridgeAddr string, rules []string) {
		m, err := tunnel.New(&tunnel.Config{
			ServerAddr:              bridgeAddr,
			ServerAddrTCP:           bridgeAddr,
			Transport:               transports[0],
			PSK:                     tunnelPSK,
			KeepaliveInterval:       30 * time.Second,
			QualityMissedKeepalives: 3,
			DisableAutoReconnect:    true,
			DecoyGate:               decoyGate,
			EnableASNBypass:         asnBypassEnabled,
			TLSFingerprint:          asnBypassFingerprint,
			EnableJA3Randomize:      true,
			WhisperaOptions:         whisperaOptions(cfg, whisperaSecret),
			TransportConfig:         cfg.TransportConfig,
			ForceSNI:                getGlobalSNI(),
		})
		if err != nil {
			stdlog.Printf("[multi-bridge] build tunnel %s failed: %v", bridgeID, err)
			return
		}
		m.SetDependencies(nil, hsMod, cryptoMod)

		entry := &TransportEntry{
			ID:               pool.NextID(),
			Transport:        transports[0],
			Server:           bridgeAddr,
			Enabled:          true,
			Obfuscated:       true,
			ForceObfuscation: true,
			Status:           connStatusConnecting,
			mgr:              m,
		}
		pool.Add(entry)

		connCtx, connCancel := context.WithCancel(bridgeCtx)
		if err := m.Init(connCtx, nil); err != nil {
			stdlog.Printf("[multi-bridge] init %s (%s) failed: %v", bridgeID, bridgeAddr, err)
			connCancel()
			entry.mu.Lock()
			entry.Status = connStatusFailed
			entry.Error = err.Error()
			entry.mu.Unlock()
			return
		}
		entry.mu.Lock()
		entry.cancel = connCancel
		entry.mu.Unlock()

		if err := m.Connect(connCtx); err != nil {
			stdlog.Printf("[multi-bridge] connect %s (%s) failed: %v", bridgeID, bridgeAddr, err)
			entry.mu.Lock()
			entry.Status = connStatusFailed
			entry.Error = err.Error()
			entry.mu.Unlock()
			connCancel()
			return
		}
		entry.mu.Lock()
		entry.Status = connStatusConnected
		entry.ConnectedAt = time.Now()
		entry.mu.Unlock()
		stdlog.Printf("[multi-bridge] bridge %s connected (%s), rules: %v", bridgeID, bridgeAddr, rules)
		if err := multiRouter.AttachBridgeTunnel(bridgeID, m); err != nil {
			stdlog.Printf("[multi-bridge] bridge %s attach error: %v", bridgeID, err)
		}
	}

	effectiveSubURL := *subURL
	if effectiveSubURL == "" && cfg != nil {
		effectiveSubURL = cfg.SubscriptionURL
	}
	if effectiveSubURL == "" && *connKey != "" {
		if ck, err := config.ParseConnectionKey(*connKey); err == nil {
			effectiveSubURL = ck.SubscriptionURL
		}
	}

	var globalSubMgr *config.SubscriptionManager
	if effectiveSubURL != "" {
		stdlog.Printf("Subscription URL: %s (refresh every %s)", effectiveSubURL, *subInterval)
		globalSubMgr = config.NewSubscriptionManager(effectiveSubURL, *subInterval, func(keys []*config.ConnectionKey) {
			if len(keys) == 0 {
				return
			}
			best := keys[0]
			stdlog.Printf("Subscription updated: %d keys available, using %q (server=%s)", len(keys), best.Name, best.Server)
			if best.Server != "" && best.Server != serverAddress {
				serverAddress = best.Server
				stdlog.Printf("Subscription: server address updated to %s", serverAddress)
			}
		})
		globalSubMgr.Start()
		defer globalSubMgr.Stop()
		globalSubscriptionMgr = globalSubMgr
	}

	startControlServer(ctx)

	if err := lc.Start(); err != nil {
		fatalf("Failed to start: %v", err)
	}

	stdlog.Printf("Connecting to VPN server: %s via %s", serverAddress, transports[0])

	var ks *killswitch.KillSwitch
	if *enableKillSwitch {
		var err error
		ks, err = killswitch.New(&killswitch.Config{
			Enabled:  true,
			AllowLAN: *allowLAN,
			AllowDNS: true,
		})
		if err != nil {
			stdlog.Printf("WARNING: Failed to create kill switch: %v", err)
		}
	}

	if err := tunnelMod.Connect(ctx); err != nil {
		stdlog.Printf("WARNING: Failed to connect to proxy server: %v", err)
		primaryEntry.mu.Lock()
		primaryEntry.Status = connStatusFailed
		primaryEntry.Error = err.Error()
		primaryEntry.mu.Unlock()

		for i, m := range extraTunnels {
			if pool.AnyConnected() {
				socksMod.SetTunnel(m)
				stdlog.Printf("Switched to transport %s", transports[i+1])
				break
			}
		}
		if !pool.AnyConnected() {
			stdlog.Printf("Tunnel down — fail-closed: non-bypass traffic refused until reconnect (no unencrypted fallback); watchdog retrying")
		}
	} else {
		primaryEntry.mu.Lock()
		primaryEntry.Status = connStatusConnected
		primaryEntry.ConnectedAt = time.Now()
		primaryEntry.mu.Unlock()
		stdlog.Printf("Connected to proxy server via %s", transports[0])

		dnsMod.SetDialContext(tunnelMod.DialStream)
		stdlog.Printf("DNS now routed through tunnel")

		if *noInternalTun {
			stdlog.Printf("External TUN mode: external router will handle TUN/routing")
			stdlog.Printf("SOCKS5 proxy ready at %s", *socksAddr)
			if host, _, err := net.SplitHostPort(serverAddress); err == nil {
				proxyServerIP := net.ParseIP(host)
				proxyPort := 8443
				if p, err := net.DefaultResolver.LookupPort(context.Background(), "tcp", "8443"); err == nil {
					proxyPort = p
				}

				if ks != nil && proxyServerIP != nil {
					ks.SetVPNServer(proxyServerIP, proxyPort)
					if err := ks.Enable(); err != nil {
						stdlog.Printf("WARNING: Failed to enable kill switch: %v", err)
					} else {
						stdlog.Printf("Kill Switch ENABLED - traffic blocked except to %s", host)
					}
				}
			}
		} else {
			if host, _, err := net.SplitHostPort(serverAddress); err == nil {
				stdlog.Printf("proxy server IP for routing: %s", host)
			}
		}
	}

	stdlog.Printf("SOCKS5 proxy listening on %s", *socksAddr)

	go runTransportWatchdog(ctx, primaryEntry, transports, socksMod, restartEntry, buildBaseCfg)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sigChan:
	case <-ctx.Done():
	}
}
