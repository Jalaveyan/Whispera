package client

import (
	"context"
	"encoding/base64"
	stdlog "log"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nekoskin/whispera/common/dns"
	"github.com/nekoskin/whispera/common/split_tunnel"
	"github.com/nekoskin/whispera/core/config"
	"github.com/nekoskin/whispera/core/protocol/fingerprint"
	"github.com/nekoskin/whispera/core/socks5"
	"github.com/nekoskin/whispera/core/tunnel"
)

const defaultDNSUpstream = "1.1.1.1:53"

func newBypassDNSResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 1 * time.Second}
			return d.DialContext(ctx, "udp", *bypassDNS)
		},
	}
}

func setupSplitTunnel(cfg *config.ClientConfig) *split_tunnel.SplitTunnelManager {
	stm := split_tunnel.NewSplitTunnelManager()
	stm.CreateDefaultRules()
	if err := stm.LoadAppRules(*splitRulesJSON); err != nil {
		stdlog.Printf("WARNING: split tunnel rules load failed: %v", err)
	}
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

	return stm
}

func startGeoIPRefresh(ctx context.Context, stm *split_tunnel.SplitTunnelManager, dnsMod *dns.Resolver, dial func(context.Context, string, string) (net.Conn, error)) {
	geo := split_tunnel.NewGeoIPSet()
	stm.SetGeoIP(geo)
	stm.SetResolver(dnsMod.ResolveUpstream)

	client := &http.Client{
		Timeout:   90 * time.Second,
		Transport: &http.Transport{DialContext: dial},
	}
	go geo.KeepFresh(ctx, client, geoIPCachePath())
}

func geoIPCachePath() string {
	if *logFilePath != "" {
		return filepath.Join(filepath.Dir(*logFilePath), "geoip-ru.txt")
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "whispera", "geoip-ru.txt")
}

func resolveServerAddress(cfg *config.ClientConfig, resolvedTransport string) string {
	addr := pickServerAddress(cfg, resolvedTransport)
	if addr == "" {
		addr = cfg.Server
	}
	if addr == "" {
		return ""
	}
	return addr
}

func resolveFingerprintSettings(cfg *config.ClientConfig) (bool, string) {
	enabled := *asnBypass
	name := *tlsFingerprint
	if cfg.ASNBypass != nil && cfg.ASNBypass.Enabled {
		enabled = true
		if cfg.ASNBypass.TLSFingerprint != "" {
			name = cfg.ASNBypass.TLSFingerprint
		}
	}

	if *forceFingerprint != "" {
		return enabled, name
	}
	if name != "" && !fingerprint.Generating() {
		fingerprint.SetForced(name)
	}
	if cfg.WhisperaFPRaw != "" {
		if raw, err := base64.StdEncoding.DecodeString(cfg.WhisperaFPRaw); err == nil {
			fingerprint.SetForcedRaw(raw)
		}
	}
	return enabled, name
}

func resolveKeys(cfg *config.ClientConfig) (whisperaSecret, tunnelPSK []byte) {
	if cfg.PSK == "" {
		return nil, nil
	}
	pskBytes, err := base64.StdEncoding.DecodeString(cfg.PSK)
	if err != nil || len(pskBytes) != 32 {
		return nil, nil
	}
	if cfg.WhisperaAddr != "" {
		whisperaSecret = pskBytes
	}
	return whisperaSecret, pskBytes
}

func applySNIOverride(cfg *config.ClientConfig) {
	sni := *forceSNIFlag
	if sni == "" {
		sni = cfg.ForceSNI
	}
	if sni == "" {
		return
	}
	globalForceSNI.Store(sni)
	stdlog.Printf("SNI override active: all connections will use SNI=%q", sni)
}

func resolveTransportList(cfg *config.ClientConfig) []string {
	active := cfg.Transport
	if active == "" {
		active = *transport
	}

	var transports []string
	for _, t := range strings.Split(active, ",") {
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
	return transports
}

func resolveRuntimeParams(cfg *config.ClientConfig) *clientRuntimeParams {
	resolvedTransport := cfg.Transport
	if resolvedTransport == "" {
		resolvedTransport = *transport
	}

	asnBypassEnabled, _ := resolveFingerprintSettings(cfg)
	whisperaSecret, tunnelPSK := resolveKeys(cfg)

	if *russianService != "" {
		cfg.RussianService = *russianService
		stdlog.Printf("Override: Russian Service masquerading enabled: %s", cfg.RussianService)
	}
	applySNIOverride(cfg)

	return &clientRuntimeParams{
		serverAddress:    resolveServerAddress(cfg, resolvedTransport),
		asnBypassEnabled: asnBypassEnabled,
		whisperaSecret:   whisperaSecret,
		tunnelPSK:        tunnelPSK,
		transports:       resolveTransportList(cfg),
	}
}

func setupNetworking(cfg *config.ClientConfig) (*socks5.Module, *dns.Resolver, *split_tunnel.SplitTunnelManager) {
	dnsUpstreamAddr := defaultDNSUpstream
	if strings.EqualFold(*dnsUpstream, "system") {
		dnsUpstreamAddr = ""
	} else if *dnsUpstream != "" {
		dnsUpstreamAddr = *dnsUpstream
	}
	bypassDNSResolver := newBypassDNSResolver()
	stm := setupSplitTunnel(cfg)

	socksMod, _ := socks5.New(&socks5.Config{
		ListenAddr:    *socksAddr,
		Debug:         true,
		MTU:           cfg.MTU,
		BypassFunc:    stm.ShouldBypass,
		BlockTorrents: true,
	})
	generateSocksAuth()
	socksMod.SetAuthHandler(socksUser, socksPass)
	stdlog.Printf("SOCKS5 auth enabled (user=%s)", socksUser)
	fingerprint.SetCollectDir(filepath.Join(mlDefaultDataDir(), "fingerprints"))
	socks5.CollectHook = func(b []byte) { _ = fingerprint.CollectRawClientHello(b) }

	dnsMod, _ := dns.New(&dns.Config{
		Upstream:       dnsUpstreamAddr,
		CacheEnabled:   true,
		BypassFunc:     stm.ShouldBypassByHostname,
		BypassResolver: bypassDNSResolver,
	})
	return socksMod, dnsMod, stm
}

func logDeviceID() {
	if !*hwidFlag {
		stdlog.Printf("HWID disabled: using a random per-connection ID")
		return
	}
	if deviceID, err := loadOrCreateDeviceID(); err == nil {
		stdlog.Printf("Device ID: %x", deviceID[:8])
	} else {
		stdlog.Printf("WARNING: Could not load/create device ID: %v", err)
	}
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
		WhisperaSelPub:   cfg.WhisperaSelPub,
		EnableGRPC:       cfg.GRPCAddr != "",
		GRPCAddr:         cfg.GRPCAddr,
		GRPCServerName:   cfg.GRPCServerName,
		GRPCUseTLS:       cfg.GRPCUseTLS,
		EnableYaDisk:     cfg.YaDiskOAuthToken != "",
		YaDiskOAuthToken: cfg.YaDiskOAuthToken,
		YaDiskSessionID:  cfg.YaDiskSessionID,
	}
}
