package client

import (
	"context"
	"encoding/base64"
	stdlog "log"
	mrand "math/rand"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/nekoskin/whispera/common/dns"
	"github.com/nekoskin/whispera/common/split_tunnel"
	"github.com/nekoskin/whispera/core/config"
	"github.com/nekoskin/whispera/core/crypto"
	"github.com/nekoskin/whispera/core/handshake"
	"github.com/nekoskin/whispera/core/protocol/fingerprint"
	"github.com/nekoskin/whispera/core/session"
	"github.com/nekoskin/whispera/core/socks5"
	"github.com/nekoskin/whispera/core/tunnel"
)

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
		fingerprint.SetForced(asnBypassFingerprint)
	}
	if *forceFingerprint == "" && cfg.WhisperaFPRaw != "" {
		if raw, err := base64.StdEncoding.DecodeString(cfg.WhisperaFPRaw); err == nil {
			fingerprint.SetForcedRaw(raw)
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

	fallbackTCP := cfg.ServerTCP
	if fallbackTCP == "" {
		fallbackTCP = cfg.Server
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
	fingerprint.SetCollectDir(filepath.Join(mlDefaultDataDir(), "fingerprints"))
	socks5.CollectHook = func(b []byte) { _ = fingerprint.CollectRawClientHello(b) }

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
	if deviceID, err := loadOrCreateDeviceID(); err == nil {
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
