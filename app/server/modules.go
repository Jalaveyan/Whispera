package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	logger "github.com/nekoskin/whispera/common/log"
	server "github.com/nekoskin/whispera/core/manager"
	"github.com/nekoskin/whispera/core/relay"

	"github.com/nekoskin/whispera/common/runtime/lifecycle"
	"github.com/nekoskin/whispera/common/update"
	"github.com/nekoskin/whispera/core/apiserver"
	"github.com/nekoskin/whispera/core/config"
	"github.com/nekoskin/whispera/core/outbound"
	"github.com/nekoskin/whispera/core/probedetector"
	"github.com/nekoskin/whispera/core/router"
)

func createModules(manager *lifecycle.Manager, ctx context.Context) error {
	configProvider, err := config.New(*configFile)
	if err != nil {
		return err
	}
	if err := manager.Register(configProvider); err != nil {
		return err
	}

	var serverConfig *config.ServerConfig
	if *configFile != "" {
		if err := configProvider.Load(*configFile); err != nil {
			return err
		}
		serverConfig = configProvider.GetConfig()
	} else {
		serverConfig = config.DefaultServerConfig()
	}

	if !*debug && serverConfig.Logging.Level != "" {
		log.SetLevel(logger.ParseLevel(serverConfig.Logging.Level))
	}

	if serverConfig.API.AuthToken == "" && *configFile != "" {
		tokenBytes := make([]byte, 32)
		if _, err := rand.Read(tokenBytes); err == nil {
			newToken := base64.StdEncoding.EncodeToString(tokenBytes)
			if err := configProvider.Update(func(c *config.ServerConfig) {
				c.API.AuthToken = newToken
			}); err == nil {
				serverConfig = configProvider.GetConfig()
			}
		}
	}

	if serverConfig.API.AdminUsername == "admin" && serverConfig.API.AdminPassword == "admin" {
		fmt.Println("The default login and username are not secure and need to be changed:")
	}

	server.Global.SetCallbacks(
		func(inbound config.InboundConfig) error {
			if inbound.Mode == "reverse" {
				go StartReverseInbound(inbound, ctx.Done())
				return nil
			}
			return StartInbound(inbound, serverConfig)
		},
		func(tag string) error {
			return StopInbound(tag)
		},
	)

	if *listenAddr != "" {
		serverConfig.Server.ListenAddr = *listenAddr
	}
	if *apiAddr != "" {
		serverConfig.API.ListenAddr = *apiAddr
	}

	if err := initCore(manager, serverConfig); err != nil {
		return err
	}
	if err := initTransports(manager, serverConfig, ctx, configProvider); err != nil {
		return err
	}

	return initOptional(manager, serverConfig, ctx)
}

func initCore(m *lifecycle.Manager, sc *config.ServerConfig) error {
	routerEngine, err := router.New(&router.Config{
		MaxRules:    1000,
		EnableCache: true,
		CacheSize:   10000,
	})
	if err != nil {
		return err
	}
	globalRouter = routerEngine
	if err := m.Register(routerEngine); err != nil {
		return err
	}

	if geo := sc.Routing.Geo; geo.Enabled {
		dir := "/var/lib/whispera/geo"
		if geo.GeoIPFile != "" {
			_ = routerEngine.LoadGeoIPFile(geo.GeoIPFile)
		} else if geo.GeoSiteFile != "" {
			_ = routerEngine.LoadGeoSiteFile(geo.GeoSiteFile)
		} else {
			_ = routerEngine.LoadGeoData(dir)
		}
	}

	globalOutbound = outbound.NewOutboundManager()

	return nil
}

func initTransports(m *lifecycle.Manager, sc *config.ServerConfig, ctx context.Context, cfgProvider *config.Provider) error {
	relayServer, err := relay.New(&relay.Config{
		MaxStreams:     sc.Relay.MaxStreams,
		EnableTCP:      sc.Relay.EnableTCP,
		EnableUDP:      sc.Relay.EnableUDP,
		Debug:          sc.Relay.Debug || *debug,
		UpstreamProxy:  sc.Relay.UpstreamProxy,
		PaddingMaxSize: sc.Obfuscation.Padding.MaxSize,
	})
	if err != nil {
		return err
	}

	globalRelay = relayServer
	relayServer.SetRouter(globalRouter)

	if om := globalOutbound; om != nil {
		relayServer.SetOutboundDial(om.Dial)
		om.UpdateOutbounds(sc.Outbounds)
		outboundsCh := cfgProvider.Watch("outbounds")
		go func() {
			for val := range outboundsCh {
				if outbounds, ok := val.([]config.OutboundConfig); ok {
					om.UpdateOutbounds(outbounds)
				}
			}
		}()
	}

	if err := m.Register(relayServer); err != nil {
		return err
	}

	if len(sc.Inbounds) > 0 {
		startConfiguredInbounds(sc, ctx)
		return nil
	}
	if sc.Transport.TCP.Enabled {
		return startFallbackTCP(m, sc)
	}
	return nil
}

func initOptional(m *lifecycle.Manager, sc *config.ServerConfig, ctx context.Context) error {
	if sc.API.Enabled {
		if err := initAPIServer(m, sc); err != nil {
			return err
		}
	}

	if sc.Whispera.Enabled && sc.Whispera.Domain == "" {
		ensureWhisperaServerCert(sc)
	}

	if sc.Whispera.Enabled && (sc.Whispera.TLSCert != "" || sc.Whispera.Domain != "") {
		initWhispera(m, sc, ctx)
	}

	if err := initGRPC(m, sc); err != nil {
		return err
	}

	if err := initYaDisk(m, sc); err != nil {
		return err
	}

	if sc.Update.Enabled && sc.Update.ManifestURL != "" {
		initUpdater(m, sc)
	}

	return nil
}

func initAPIServer(m *lifecycle.Manager, sc *config.ServerConfig) error {
	apiServer, err := apiserver.New(&apiserver.Config{
		Enabled:           true,
		ListenAddr:        sc.API.ListenAddr,
		AuthToken:         sc.API.AuthToken,
		WebRoot:           sc.API.WebRoot,
		EnableCORS:        true,
		AdminUsername:     sc.API.AdminUsername,
		AdminPassword:     sc.API.AdminPassword,
		AdminPasswordHash: sc.API.AdminPasswordHash,
		LoginRateLimit:    sc.API.LoginRateLimit,
	})
	if err != nil {
		return err
	}

	apiServer.SetRegistry(m.Registry())
	apiServer.SetKeyLimits(globalKeyLimits)

	if err := m.Register(apiServer); err != nil {
		return err
	}

	globalProbeDetector = probedetector.New(probedetector.DefaultConfig())
	globalProbeDetector.Start()
	apiServer.SetProbeDetector(globalProbeDetector)

	return nil
}

func initUpdater(m *lifecycle.Manager, sc *config.ServerConfig) {
	updateConfig := &update.Config{
		ManifestURL:    sc.Update.ManifestURL,
		CurrentVersion: Version,
		CheckInterval:  sc.Update.CheckInterval.D(),
	}
	if sc.Update.PublicKey != "" {
		if pk, err := hex.DecodeString(sc.Update.PublicKey); err == nil && len(pk) == ed25519.PublicKeySize {
			updateConfig.PublicKey = ed25519.PublicKey(pk)
		} else {
			log.Warn("update: public_key is set but invalid (must be %d-byte hex) — signature verification disabled", ed25519.PublicKeySize)
		}
	}
	if updateConfig.CheckInterval <= 0 {
		updateConfig.CheckInterval = 1 * time.Hour
	}
	binaryPath, _ := os.Executable()
	updateConfig.BinaryPath = binaryPath
	globalUpdater = update.NewUpdater(updateConfig)
	globalUpdater.Start()
	m.OnShutdown(func() { globalUpdater.Stop() })
}
