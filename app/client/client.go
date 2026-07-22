package client

import (
	"context"
	"encoding/base64"
	"flag"
	"github.com/nekoskin/whispera/app/auth"
	"github.com/nekoskin/whispera/common/dns"
	"github.com/nekoskin/whispera/common/log"
	"github.com/nekoskin/whispera/common/runtime/lifecycle"
	"github.com/nekoskin/whispera/common/split_tunnel"
	"github.com/nekoskin/whispera/core/agent"
	"github.com/nekoskin/whispera/core/config"
	"github.com/nekoskin/whispera/core/crypto"
	"github.com/nekoskin/whispera/core/handshake"
	"github.com/nekoskin/whispera/core/killswitch"
	"github.com/nekoskin/whispera/core/protocol"
	"github.com/nekoskin/whispera/core/session"
	"github.com/nekoskin/whispera/core/socks5"
	"github.com/nekoskin/whispera/core/tunnel"
	"io"
	stdlog "log"
	mrand "math/rand"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

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
	srvList              []string
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
	serverList       = flag.String("servers", "", "Comma-separated server addresses for latency-based routing")
	mlServerURL      = flag.String("ml-server", "", "ML server URL (e.g. https://127.0.0.1:8000)")
	mlTokenFlag      = flag.String("ml-token", "", "ML API auth token")
	controlPort      = flag.String("control-port", "10801", "Control server port (default 10801)")
	dnsUpstream      = flag.String("dns", "", "DNS upstream: host:port for UDP (8.8.8.8:53), https://... for DoH (https://1.1.1.1/dns-query). Empty = 1.1.1.1:53. 'system' = ISP resolver")
	spoofIPs         = flag.String("spoof-ips", "", "Comma-separated source IPs for IP spoofing (requires multiple local IPs)")
	adminTokenFlag   = flag.String("admin-token", "", "Admin token required for privileged control endpoints (e.g. /spoof). Empty = no auth")
	tlsFragSize      = flag.Int("tls-fragment", 0, "TLS ClientHello fragment size in bytes (0=default 40, range 16-200). Smaller = harder for DPI but more RTT")
	logFilePath      = flag.String("log-file", "", "Write logs to file (default: in-memory only, no disk storage)")
	forceSNIFlag     = flag.String("sni", "", "Force custom SNI in TLS ClientHello for all connections (e.g. www.google.com). Overrides asn-bypass SNI")
	regionFlag       = flag.String("region", "", "Preferred server region: auto|ru|eu|us|cn (overrides config)")
	subURL           = flag.String("sub-url", "", "Subscription URL for automatic key refresh (checked every 24h)")
	subInterval      = flag.Duration("sub-interval", 24*time.Hour, "Subscription refresh interval")
	bypassDNS        = flag.String("bypass-dns", "77.88.8.8:53", "DNS server used for bypass resolver (never goes through tunnel)")
	hwidFlag         = flag.Bool("hwid", true, "Send a persistent per-device ID in the handshake (false = random ID per connection)")
	forceFingerprint = flag.String("force-fingerprint", "", "Force a specific TLS fingerprint for the main tunnel handshake: chrome, chrome_120, chrome_115, firefox, firefox_120, safari, ios, android, edge. Empty = auto/random (default)")
)

func pickServerAddress(cfg *config.ClientConfig, transport string) string {
	switch transport {
	case "tcp", "tls":
		if cfg.ServerTCP != "" {
			return cfg.ServerTCP
		}
	case "ws", "websocket":
		if cfg.ServerWS != "" {
			return cfg.ServerWS
		}
		if cfg.ServerTCP != "" {
			return cfg.ServerTCP
		}
	}
	if cfg.Server != "" {
		return cfg.Server
	}
	return cfg.ServerTCP
}

func mlDefaultDataDir() string {
	if exe, err := os.Executable(); err == nil {
		exeDir := strings.TrimSuffix(exe, "/"+strings.Split(exe, "/")[len(strings.Split(exe, "/"))-1])
		if fi, err := os.Stat(exeDir + "/data/api_token"); err == nil && !fi.IsDir() {
			return exeDir + "/data"
		}
	}
	switch {
	case strings.EqualFold(os.Getenv("OS"), "Windows_NT") || os.PathSeparator == '\\':
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			return appdata + `\Whispera`
		}
	default:
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			return xdg + "/whispera"
		}
		if home, err := os.UserHomeDir(); err == nil {
			return home + "/.config/whispera"
		}
	}
	return "data"
}

func resolveMLToken(cfg *config.ClientConfig) string {
	if cfg.MLServerURL == "" {
		return ""
	}
	if cfg.MLToken != "" {
		return cfg.MLToken
	}

	candidates := []string{mlDefaultDataDir() + string(os.PathSeparator) + "api_token"}
	if cfg.MLTokenFile != "" {
		candidates = append([]string{cfg.MLTokenFile}, candidates...)
	}

	for _, path := range candidates {
		if data, err := os.ReadFile(path); err == nil {
			if tok := strings.TrimSpace(string(data)); tok != "" {
				return tok
			}
		}
	}

	stdlog.Printf("WARNING: MLServerURL set but no API token found — requests may be rejected (401)")
	return ""
}

func setupLogging() {
	underSystemd := os.Getenv("JOURNAL_STREAM") != "" || os.Getenv("INVOCATION_ID") != ""

	var logWriter io.Writer
	if *logFilePath != "" {
		logFile, err := os.OpenFile(*logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			rb := newRingLogBuffer(2000)
			globalLogBuf = rb
			logWriter = rb
		} else {
			logWriter = logFile
		}
	} else if underSystemd {
		logWriter = os.Stdout
	} else {
		if null, errNull := os.OpenFile(os.DevNull, os.O_WRONLY, 0666); errNull == nil {
			os.Stdout = null
			os.Stderr = null
		}
		rb := newRingLogBuffer(2000)
		globalLogBuf = rb
		logWriter = rb
	}
	stdlog.SetOutput(logWriter)
	log.SetOutput(logWriter)
	log = logger.Module("client")
	stdlog.Printf("Whispera Client v%s starting...", Version)
}

func loadClientConfig() *config.ClientConfig {
	var cfg *config.ClientConfig

	if *connKey != "" {
		key, err := config.ParseConnectionKey(*connKey)
		if err != nil {
			fatalf("Failed to parse connection key: %v", err)
		}
		cfg = key.ToClientConfig()
		stdlog.Printf("Loaded config from key: %s", key.Name)
		stdlog.Printf("Server: %s (transport: %s, obfuscation: %s)", key.GetPrimaryServer(), key.Transport, key.ObfsPreset)
	} else if *configPath != "" {
		var loadErr error
		cfg, loadErr = config.LoadClient(*configPath)
		if loadErr != nil {
			fatalf("Failed to load config: %v", loadErr)
		}
	} else {
		cfg = &config.ClientConfig{
			Server: *serverAddr,
		}
	}

	if *connKey == "" && *serverAddr != "" {
		cfg.Server = *serverAddr
	}

	if *mlServerURL != "" {
		cfg.MLServerURL = *mlServerURL
	}
	if *mlTokenFlag != "" {
		cfg.MLToken = *mlTokenFlag
	}

	if *userKey != "" && cfg.PSK == "" {
		cfg.PSK = *userKey
		stdlog.Printf("ML mode: user-key PSK set")
	}

	if cfg.Server == "" && cfg.ServerTCP == "" {
		fatalf("No server address specified. Use -server, -key, or -config")
	}

	stdlog.Printf("Starting Whispera Client v%s", Version)
	stdlog.Printf("Server: %s", cfg.Server)
	if cfg.ServerTCP != "" {
		stdlog.Printf("TCP Fallback: %s", cfg.ServerTCP)
	}
	if cfg.ObfsPreset != "" {
		stdlog.Printf("Obfuscation: %s", cfg.ObfsPreset)
	}

	return cfg
}

func newBypassDNSResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 1 * time.Second}
			return d.DialContext(ctx, "udp", *bypassDNS)
		},
	}
}

func setupSplitTunnel(cfg *config.ClientConfig, bypassDNS *net.Resolver) *split_tunnel.SplitTunnelManager {
	stm := split_tunnel.NewSplitTunnelManager()
	stm.AddRussianWhitelist()
	stm.CreateDefaultRules()
	if cfg.SplitTunnel {
		stm.SetEnabled(true)
		if cfg.SplitTunnelMode != "" {
			stm.SetMode(cfg.SplitTunnelMode)
		}
		if cfg.SplitTunnelRules != "" {
			if err := stm.LoadConfig(cfg.SplitTunnelRules); err != nil {
				stdlog.Printf("WARNING: split tunnel config load failed: %v", err)
			}
		}
	} else {
		stm.SetEnabled(true)
	}

	go func() {
		resolveCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		n := stm.PreResolveAndCacheIPs(resolveCtx, bypassDNS)
		stdlog.Printf("[split-tunnel] pre-resolved %d Russian bypass IPs", n)
	}()

	return stm
}

func resolveRuntimeParams(cfg *config.ClientConfig) *clientRuntimeParams {
	resolvedTransport := cfg.Transport
	if resolvedTransport == "" {
		resolvedTransport = *transport
	}

	serverAddress := pickServerAddress(cfg, resolvedTransport)
	if serverAddress == "" {
		serverAddress = cfg.Server
	}
	if serverAddress != "" {
		if _, _, err := net.SplitHostPort(serverAddress); err != nil {
			serverAddress = net.JoinHostPort(serverAddress, "8443")
		}
	}

	asnBypassEnabled := *asnBypass
	asnBypassFingerprint := *tlsFingerprint
	if cfg.ASNBypass != nil && cfg.ASNBypass.Enabled {
		asnBypassEnabled = true
		if cfg.ASNBypass.TLSFingerprint != "" {
			asnBypassFingerprint = cfg.ASNBypass.TLSFingerprint
		}
	}

	if *forceFingerprint == "" && asnBypassFingerprint != "" {
		protocol.SetForcedFingerprint(asnBypassFingerprint)
	}
	if *forceFingerprint == "" && cfg.WhisperaFPRaw != "" {
		if raw, err := base64.StdEncoding.DecodeString(cfg.WhisperaFPRaw); err == nil {
			protocol.SetForcedRawFingerprint(raw)
		}
	}

	var whisperaSecret []byte
	var tunnelPSK []byte

	if cfg.PSK != "" {
		if pskBytes, err := base64.StdEncoding.DecodeString(cfg.PSK); err == nil && len(pskBytes) == 32 {
			tunnelPSK = pskBytes
			if cfg.WhisperaAddr != "" {
				whisperaSecret = pskBytes
			}
		}
	}

	if *russianService != "" {
		cfg.RussianService = *russianService
		stdlog.Printf("Override: Russian Service masquerading enabled: %s", cfg.RussianService)
	}

	activeForceSNI := *forceSNIFlag
	if activeForceSNI == "" {
		activeForceSNI = cfg.ForceSNI
	}
	if activeForceSNI != "" {
		globalForceSNI.Store(activeForceSNI)
		stdlog.Printf("SNI override active: all connections will use SNI=%q", activeForceSNI)
	}

	activeRegion := *regionFlag
	if activeRegion == "" {
		activeRegion = cfg.PreferredRegion
	}
	if activeRegion == "" {
		activeRegion = "auto"
	}
	globalRegion.Store(activeRegion)
	if len(cfg.Regions) > 0 {
		cfgRegions = cfg.Regions
	}
	if activeRegion != "auto" {
		stdlog.Printf("Region: %s", activeRegion)
	}

	fallbackTCP := cfg.ServerTCP
	if fallbackTCP == "" {
		fallbackTCP = cfg.Server
	}

	var srvList []string
	if *serverList != "" {
		for _, s := range strings.Split(*serverList, ",") {
			if s = strings.TrimSpace(s); s != "" {
				srvList = append(srvList, s)
			}
		}
	}
	for _, alt := range cfg.ServerAlts {
		if alt = strings.TrimSpace(alt); alt != "" {
			srvList = append(srvList, alt)
		}
	}

	activeTransport := cfg.Transport
	if activeTransport == "" {
		activeTransport = *transport
	}

	var transports []string
	for _, t := range strings.Split(activeTransport, ",") {
		if t = strings.TrimSpace(t); t != "" {
			transports = append(transports, t)
		}
	}
	if len(transports) == 0 {
		transports = []string{"tcp"}
	}
	mrand.Shuffle(len(transports), func(i, j int) {
		transports[i], transports[j] = transports[j], transports[i]
	})

	return &clientRuntimeParams{
		serverAddress:        serverAddress,
		fallbackTCP:          fallbackTCP,
		asnBypassEnabled:     asnBypassEnabled,
		asnBypassFingerprint: asnBypassFingerprint,
		whisperaSecret:       whisperaSecret,
		tunnelPSK:            tunnelPSK,
		srvList:              srvList,
		transports:           transports,
	}
}

func setupNetworking(cfg *config.ClientConfig) (*socks5.Module, *dns.Resolver) {
	dnsUpstreamAddr := ""
	if *dnsUpstream != "" && !strings.EqualFold(*dnsUpstream, "system") {
		dnsUpstreamAddr = *dnsUpstream
	}
	bypassDNSResolver := newBypassDNSResolver()
	stm := setupSplitTunnel(cfg, bypassDNSResolver)

	socksMod, _ := socks5.New(&socks5.Config{
		ListenAddr:    *socksAddr,
		Debug:         true,
		VPNServerAddr: cfg.Server,
		MTU:           cfg.MTU,
		BypassFunc:    stm.ShouldBypass,
		BlockTorrents: true,
	})
	generateSocksAuth()
	socksMod.SetAuthHandler(socksUser, socksPass)
	stdlog.Printf("SOCKS5 auth enabled (user=%s)", socksUser)
	protocol.SetHarvestDir(filepath.Join(mlDefaultDataDir(), "fingerprints"))
	socks5.HarvestHook = func(b []byte) { _ = protocol.HarvestRawClientHello(b) }

	dnsMod, _ := dns.New(&dns.Config{
		Upstream:       dnsUpstreamAddr,
		CacheEnabled:   true,
		BypassFunc:     stm.ShouldBypassByHostname,
		BypassResolver: bypassDNSResolver,
	})
	return socksMod, dnsMod
}

func setupCoreModules() (*handshake.Handler, *crypto.Provider) {
	cryptoMod, _ := crypto.New(nil)
	sessMod, _ := session.New(&session.Config{MaxSessions: 10})
	hsMod, _ := handshake.New(&handshake.Config{
		RateLimit: 100,
		RateBurst: 50,
		Timeout:   10 * time.Second,
	})
	hsMod.SetDependencies(cryptoMod, sessMod)

	if !*hwidFlag {
		stdlog.Printf("HWID disabled: using a random per-connection ID")
		return hsMod, cryptoMod
	}
	if deviceID, err := auth.LoadOrCreateDeviceID(); err == nil {
		hsMod.SetDeviceID(deviceID)
		stdlog.Printf("Device ID: %x", deviceID[:8])
	} else {
		stdlog.Printf("WARNING: Could not load/create device ID: %v", err)
	}
	return hsMod, cryptoMod
}

func whisperaOptions(cfg *config.ClientConfig, whisperaSecret []byte) tunnel.WhisperaOptions {
	return tunnel.WhisperaOptions{
		EnableWhispera:   len(whisperaSecret) == 32,
		WhisperaSecret:   whisperaSecret,
		WhisperaAddr:     cfg.WhisperaAddr,
		WhisperaSNI:      cfg.WhisperaSNI,
		WhisperaQUICAddr: cfg.WhisperaQUICAddr,
		WhisperaCertPin:  cfg.WhisperaCertPin,
		WhisperaIDPub:    cfg.WhisperaIDPub,
		EnableGRPC:       cfg.GRPCAddr != "",
		GRPCAddr:         cfg.GRPCAddr,
		GRPCServerName:   cfg.GRPCServerName,
		GRPCUseTLS:       cfg.GRPCUseTLS,
		EnableYaDisk:     cfg.YaDiskOAuthToken != "",
		YaDiskOAuthToken: cfg.YaDiskOAuthToken,
		YaDiskSessionID:  cfg.YaDiskSessionID,
	}
}

func RunMain() {
	if !mobileMode {
		debug.SetGCPercent(100)
		debug.SetMemoryLimit(200 << 20)
		flag.Parse()
	}

	if *forceFingerprint != "" {
		protocol.SetForcedFingerprint(*forceFingerprint)
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
	srvList := rp.srvList
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
			DisableNeural:           cfg.DisableNeural,
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
			ServerList:              srvList,
			TransportConfig:         cfg.TransportConfig,
			MLOptions: tunnel.MLOptions{
				MLServerURL: cfg.MLServerURL,
				MLToken:     resolveMLToken(cfg),
			},
			ForceSNI:        getGlobalSNI(),
			Regions:         cfgRegions,
			PreferredRegion: getGlobalRegion(),
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
			DisableNeural:           cfg.DisableNeural,
			KeepaliveInterval:       30 * time.Second,
			QualityMissedKeepalives: 3,
			DisableAutoReconnect:    true,
			DecoyGate:               decoyGate,
			EnableASNBypass:         asnBypassEnabled,
			TLSFingerprint:          asnBypassFingerprint,
			EnableJA3Randomize:      true,
			WhisperaOptions:         whisperaOptions(cfg, whisperaSecret),
			MLOptions: tunnel.MLOptions{
				MLServerURL: cfg.MLServerURL,
				MLToken:     resolveMLToken(cfg),
				SNIModelDir: sniModelDir(),
			},
			ServerList:        srvList,
			TransportConfig:   tc,
			ForceObfuscation:  force,
			BehavioralProfile: profile,
			CustomSNI:         customSNI,
			ForceSNI:          getGlobalSNI(),
			NoSNI:             noSNI,
			Regions:           cfgRegions,
			PreferredRegion:   getGlobalRegion(),
			RateLimitKB:       rateLimitKB,
			EnableIPSpoof:     len(spoofList) > 0,
			SpoofSourceIPs:    spoofList,
			TLSFragmentSize:   *tlsFragSize,
		}
	}

	restartEntry := func(e *TransportEntry, tunnelCfg *tunnel.Config) {
		restartTransportEntry(ctx, e, tunnelCfg, hsMod, cryptoMod)
	}

	if asnBypassEnabled {
		stdlog.Printf("ASN bypass enabled (fingerprint: %s)", asnBypassFingerprint)
	}

	tunnelMod := newTunnelMod(transports[0])
	tunnelMod.SetDependencies(nil, hsMod, nil, cryptoMod)

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
		m.SetDependencies(nil, hsMod, nil, cryptoMod)

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

	agentCfg := agent.DefaultAgentConfig()
	agentCfg.ExploreRate = 0.1
	agentCfg.FailThreshold = 5
	for _, tr := range transports {
		agentCfg.Candidates = append(agentCfg.Candidates, agent.TransportCandidate{
			Name:     tr,
			Server:   serverAddress,
			Enabled:  true,
			Priority: 1.0,
		})
	}
	knownTransports := map[string]bool{}
	for _, tr := range transports {
		knownTransports[tr] = true
	}
	for _, extra := range []string{"tcp", "udp", "grpc", "quic"} {
		if !knownTransports[extra] {
			agentCfg.Candidates = append(agentCfg.Candidates, agent.TransportCandidate{
				Name:     extra,
				Server:   serverAddress,
				Enabled:  false,
				Priority: 0.5,
			})
		}
	}
	globalAgent = agent.NewProxyAgent(agentCfg)
	globalAgent.Start()
	defer globalAgent.Stop()

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
			DisableNeural:           cfg.DisableNeural,
			KeepaliveInterval:       30 * time.Second,
			QualityMissedKeepalives: 3,
			DisableAutoReconnect:    true,
			DecoyGate:               decoyGate,
			EnableASNBypass:         asnBypassEnabled,
			TLSFingerprint:          asnBypassFingerprint,
			EnableJA3Randomize:      true,
			WhisperaOptions:         whisperaOptions(cfg, whisperaSecret),
			MLOptions: tunnel.MLOptions{
				MLServerURL: cfg.MLServerURL,
				MLToken:     resolveMLToken(cfg),
			},
			TransportConfig: cfg.TransportConfig,
			ForceSNI:        getGlobalSNI(),
			Regions:         cfgRegions,
			PreferredRegion: getGlobalRegion(),
		})
		if err != nil {
			stdlog.Printf("[multi-bridge] build tunnel %s failed: %v", bridgeID, err)
			return
		}
		m.SetDependencies(nil, hsMod, nil, cryptoMod)

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

func sniModelDir() string {
	return filepath.Join(mlDefaultDataDir(), "sni_model")
}

func runTransportWatchdog(ctx context.Context, primaryEntry *TransportEntry, transports []string, socksMod *socks5.Module, restartEntry func(*TransportEntry, *tunnel.Config), buildBaseCfg func(*TransportEntry) *tunnel.Config) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	var primaryReconnecting int32
	var primaryReconnectFails int32
	const primaryReconnectBackoff = 2 * time.Second
	const primaryReconnectMaxBackoff = 10 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			primaryEntry.mu.Lock()
			currentMgr := primaryEntry.mgr
			wasConnected := primaryEntry.Status == connStatusConnected
			primaryEntry.mu.Unlock()

			if currentMgr != nil && currentMgr.IsConnected() {
				continue
			}

			lostPrimary := wasConnected && (currentMgr == nil || !currentMgr.IsConnected())
			if lostPrimary {
				reason := "tunnel reported not connected"
				if currentMgr != nil {
					if lastErr := currentMgr.LastError(); lastErr != nil {
						reason = lastErr.Error()
					}
				}
				primaryEntry.mu.Lock()
				primaryEntry.Status = connStatusRST
				primaryEntry.Error = reason
				primaryEntry.mu.Unlock()
				stdlog.Printf("Transport watchdog: primary %s is no longer connected (%s)", transports[0], reason)
			}

			activated := false
			entries := pool.List()
			for _, e := range entries {
				e.mu.Lock()
				status := e.Status
				mgr := e.mgr
				e.mu.Unlock()
				if status == connStatusConnected && mgr != nil && mgr.IsConnected() && mgr != currentMgr {
					socksMod.SetTunnel(mgr)
					stdlog.Printf("Transport watchdog: switched SOCKS to %s", e.Transport)
					activated = true
					break
				}
				if status == connStatusConnected && e != primaryEntry && (mgr == nil || !mgr.IsConnected()) {
					e.mu.Lock()
					e.Status = connStatusStandby
					e.mu.Unlock()
					stdlog.Printf("Transport watchdog: %s dropped, marking standby for retry", e.Transport)
				}
			}

			if !activated {
				for _, e := range entries {
					e.mu.Lock()
					status := e.Status
					mgr := e.mgr
					tr := e.Transport
					e.mu.Unlock()

					if status == connStatusStandby && mgr != nil {
						stdlog.Printf("Transport watchdog: activating standby transport %s", tr)

						go func(entry *TransportEntry) {
							restartEntry(entry, buildBaseCfg(entry))

							entry.mu.Lock()
							connected := entry.Status == connStatusConnected && entry.mgr != nil
							mgr := entry.mgr
							tr := entry.Transport
							entry.mu.Unlock()
							if connected && mgr.IsConnected() {
								socksMod.SetTunnel(mgr)
								stdlog.Printf("Transport watchdog: standby %s now active", tr)
							}
						}(e)
						break
					}
				}
			}

			primaryEntry.mu.Lock()
			enabled := primaryEntry.Enabled
			primaryEntry.mu.Unlock()

			if enabled && atomic.CompareAndSwapInt32(&primaryReconnecting, 0, 1) {
				go func() {
					defer atomic.StoreInt32(&primaryReconnecting, 0)
					if fails := atomic.LoadInt32(&primaryReconnectFails); fails > 0 {
						backoff := time.Duration(fails) * primaryReconnectBackoff
						if backoff > primaryReconnectMaxBackoff {
							backoff = primaryReconnectMaxBackoff
						}
						time.Sleep(backoff)
					}

					if globalAgent != nil {
						if recTr, _ := globalAgent.SelectTransport(); recTr != "" {
							primaryEntry.mu.Lock()
							if primaryEntry.Transport != recTr {
								stdlog.Printf("ProxyAgent: %s → %s for reconnect", primaryEntry.Transport, recTr)
								primaryEntry.Transport = recTr
							}
							primaryEntry.mu.Unlock()
						}
					}

					stdlog.Printf("Transport watchdog: reconnecting primary %s...", transports[0])

					targetCfg := buildBaseCfg(primaryEntry)

					restartEntry(primaryEntry, targetCfg)
					primaryEntry.mu.Lock()
					connected := primaryEntry.Status == connStatusConnected && primaryEntry.mgr != nil
					primaryEntry.mu.Unlock()
					if connected {
						atomic.StoreInt32(&primaryReconnectFails, 0)
						socksMod.SetTunnel(primaryEntry.mgr)
						stdlog.Printf("Transport watchdog: primary reconnected, SOCKS restored")
					} else {
						atomic.AddInt32(&primaryReconnectFails, 1)
					}
				}()
			}
		}
	}
}

func restartTransportEntry(ctx context.Context, e *TransportEntry, tunnelCfg *tunnel.Config, hsMod *handshake.Handler, cryptoMod *crypto.Provider) {
	if !atomic.CompareAndSwapInt32(&e.restarting, 0, 1) {
		return
	}
	defer atomic.StoreInt32(&e.restarting, 0)

	e.mu.Lock()
	if e.cancel != nil {
		e.cancel()
	}
	oldMgr := e.mgr
	e.Status = connStatusConnecting
	e.Error = ""
	e.mu.Unlock()

	if oldMgr != nil {
		oldMgr.Stop()
	}

	newMgr, err := tunnel.New(tunnelCfg)
	if err != nil {
		stdlog.Printf("restartEntry %s build failed: %v", e.ID, err)
		e.mu.Lock()
		e.Status = connStatusFailed
		e.Error = err.Error()
		e.mu.Unlock()
		return
	}
	newMgr.SetDependencies(nil, hsMod, nil, cryptoMod)
	if tunnelCfg.BehavioralProfile != "" {
		if err := newMgr.SetBehavioralProfile(tunnelCfg.BehavioralProfile); err != nil {
			stdlog.Printf("restartEntry %s: set profile %q: %v", e.ID, tunnelCfg.BehavioralProfile, err)
		}
	}

	newCtx, newCancel := context.WithCancel(ctx)
	if err := newMgr.Init(newCtx, nil); err != nil {
		stdlog.Printf("restartEntry %s: init failed: %v", e.ID, err)
		newCancel()
		e.mu.Lock()
		e.Status = connStatusFailed
		e.Error = err.Error()
		e.mu.Unlock()
		return
	}
	e.mu.Lock()
	e.mgr = newMgr
	e.cancel = newCancel
	e.mu.Unlock()

	connStart := time.Now()
	if err := newMgr.Connect(newCtx); err != nil {
		stdlog.Printf("restartEntry %s connect failed: %v", e.ID, err)
		newCancel()
		newMgr.Stop()
		e.mu.Lock()
		e.Status = connStatusFailed
		e.Error = err.Error()
		tr := e.Transport
		e.mu.Unlock()
		if globalAgent != nil {
			globalAgent.ReportResult(agent.ProbeResult{
				Transport: tr,
				Server:    tunnelCfg.ServerAddr,
				Latency:   time.Since(connStart),
				Success:   false,
				Error:     err.Error(),
				Timestamp: time.Now(),
			})
		}
	} else {
		e.mu.Lock()
		e.Status = connStatusConnected
		e.ConnectedAt = time.Now()
		e.mu.Unlock()
		stdlog.Printf("restartEntry %s connected (encap=%v)", e.ID, tunnelCfg.CustomDialFn != nil)
		if globalAgent != nil {
			globalAgent.ReportResult(agent.ProbeResult{
				Transport: tunnelCfg.Transport,
				Server:    tunnelCfg.ServerAddr,
				Latency:   time.Since(connStart),
				Success:   true,
				Timestamp: time.Now(),
			})
		}
	}
}
