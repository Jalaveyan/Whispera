package client

import (
	"io"
	stdlog "log"
	"os"
	"strings"

	logger "github.com/nekoskin/whispera/common/log"
	"github.com/nekoskin/whispera/core/config"
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
