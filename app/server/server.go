package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	rtdebug "runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/nekoskin/whispera/app/commands"
	logger "github.com/nekoskin/whispera/common/log"
	"github.com/nekoskin/whispera/common/runtime/base"
	"github.com/nekoskin/whispera/common/runtime/lifecycle"
	"github.com/nekoskin/whispera/common/update"
	"github.com/nekoskin/whispera/core/config"
	"github.com/nekoskin/whispera/core/keylimits"
	"github.com/nekoskin/whispera/core/outbound"
	relay2 "github.com/nekoskin/whispera/core/relay"
	"github.com/nekoskin/whispera/core/router"

	_ "go.uber.org/automaxprocs"
)

var log = logger.Module("server")

const (
	whisperaCertPath     = config.ServerCert
	whisperaKeyPath      = config.ServerKey
	whisperaDecoyCertDir = config.DecoyCertDir
	whisperaIdentityFile = config.IdentityFile
)

var Version = "0.0.5"

func buildCommit() string {
	info, ok := rtdebug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	rev, dirty := "", false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return "unknown"
	}
	if len(rev) > 7 {
		rev = rev[:7]
	}
	if dirty {
		rev += "-dirty"
	}
	return rev
}

var (
	configFile     = flag.String("config", "", "Path to configuration file")
	listenAddr     = flag.String("listen", "", "UDP/TCP listen address (default from config)")
	apiAddr        = flag.String("api", ":8080", "API server listen address")
	debug          = flag.Bool("debug", false, "Enable debug logging")
	printVersion   = flag.Bool("version", false, "Print version and exit")
	validateConfig = flag.Bool("validate-config", false, "Validate configuration and exit")
	pprofAddr      = flag.String("pprof", "localhost:6060", "Pprof server listen address")
)

// В per-flow датапати каждый поток — отдельное соединение со своим session id,
// поэтому MaxActiveSessions ограничивает одновременные потоки, а не устройства:
// одна загрузка страницы легко открывает их десятки. Лимит устройств — SoftIPCap.
var globalKeyLimits = keylimits.New(keylimits.Limits{
	MaxActiveSessions: 512,
	GlobalCap:         10000,
	SoftIPCap:         5,
	BurstPerMinute:    0,
	SessionTTL:        30 * time.Minute,
})

var (
	globalOutbound *outbound.OutboundManager
	globalRelay    *relay2.Server

	globalRouter  *router.Engine
	globalUpdater *update.Updater

	activeListeners = make(map[string]net.Listener)
	listenersMutex  sync.RWMutex

	portH2CChans   = make(map[string]chan net.Conn)
	portH2CChansMu sync.Mutex
)

func runSubcommand() {
	if len(os.Args) <= 1 {
		return
	}
	switch strings.TrimSpace(os.Args[1]) {
	case "x25519":
		commands.RunX25519Cmd()
	case "pubkey":
		commands.RunPubkeyCmd()
	case "create-key":
		commands.RunCreateKeyCmd()
	case "delete-key":
		commands.RunDeleteKeyCmd()
	case "gen-decoy-cert":
		commands.RunGenDecoyCertCmd()
	case "generate-sub":
		commands.RunGenerateSubCmd()
	case "view-keys":
		commands.RunViewKeysCmd()
	case "update-checksum":
		commands.RunUpdateChecksumCmd()
	case "set-multilistener-port":
		commands.RunSetMultilistenerPortCmd()
	}
}

func startProfiling() {
	runtime.SetBlockProfileRate(10000)
	runtime.SetMutexProfileFraction(100)
	go func() {
		if err := http.ListenAndServe(*pprofAddr, nil); err != nil {
			log.Warn("pprof server on %s exited: %v", *pprofAddr, err)
		}
	}()
}

func main() {
	runSubcommand()

	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[PANIC] Whispera Server: %v\n", r)
			os.Exit(2)
		}
	}()

	flag.Parse()
	if *configFile == "" {
		*configFile = "config.yaml"
	}
	if *debug {
		log.SetLevel(logger.LevelDebug)
	}
	if *printVersion {
		fmt.Printf("Whispera %s (%s)\n", Version, buildCommit())
		os.Exit(0)
	}
	startProfiling()

	manager := lifecycle.NewManager(lifecycle.Config{
		ShutdownTimeout: 30 * time.Second,
	})

	memWatchdog := base.NewMemoryWatchdog(512, 1024, 30*time.Second)
	memWatchdog.Start()
	manager.OnShutdown(func() { memWatchdog.Stop() })

	moduleCtx, moduleCancel := context.WithCancel(context.Background())
	manager.OnShutdown(moduleCancel)

	if err := createModules(manager, moduleCtx); err != nil {
		log.Fatalf("Failed to create modules: %v", err)
	}
	if *validateConfig {
		os.Exit(0)
	}
	if err := manager.Run(); err != nil {
		log.Fatalf("Application error: %v", err)
	}
}
