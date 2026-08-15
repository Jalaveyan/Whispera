package client

import (
	"bytes"
	"io"
	stdlog "log"
	"os"
	"strings"
	"sync"
	"time"

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

const (
	logKeepBytes = 256 << 10
	logTrimEvery = time.Hour
)

type trimmingLog struct {
	mu   sync.Mutex
	f    *os.File
	path string
}

var (
	currentLog   *trimmingLog
	currentLogMu sync.Mutex
)

func openTrimmingLog(path string) (*trimmingLog, error) {
	currentLogMu.Lock()
	defer currentLogMu.Unlock()

	if currentLog != nil {
		if err := currentLog.reopen(path); err != nil {
			return nil, err
		}
		return currentLog, nil
	}

	t, err := newTrimmingLog(path)
	if err != nil {
		return nil, err
	}
	currentLog = t
	go t.keepTrimmed()
	return t, nil
}

func (t *trimmingLog) reopen(path string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.path == path {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	t.f.Close()
	t.f, t.path = f, path
	return nil
}

func newTrimmingLog(path string) (*trimmingLog, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	return &trimmingLog{f: f, path: path}, nil
}

func (t *trimmingLog) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.f.Write(p)
}

func (t *trimmingLog) keepTrimmed() {
	ticker := time.NewTicker(logTrimEvery)
	defer ticker.Stop()
	for range ticker.C {
		t.trim()
	}
}

func (t *trimmingLog) trim() {
	t.mu.Lock()
	defer t.mu.Unlock()

	fi, err := t.f.Stat()
	if err != nil || fi.Size() <= logKeepBytes {
		return
	}

	src, err := os.Open(t.path)
	if err != nil {
		return
	}
	tail := make([]byte, logKeepBytes)
	n, _ := src.ReadAt(tail, fi.Size()-logKeepBytes)
	src.Close()
	if n == 0 {
		return
	}
	tail = tail[:n]
	if i := bytes.IndexByte(tail, '\n'); i >= 0 {
		tail = tail[i+1:]
	}
	if err := t.f.Truncate(0); err != nil {
		return
	}
	if _, err := t.f.Seek(0, io.SeekStart); err != nil {
		return
	}
	t.f.Write(tail)
}

func setupLogging() {
	underSystemd := os.Getenv("JOURNAL_STREAM") != "" || os.Getenv("INVOCATION_ID") != ""

	var logWriter io.Writer
	if *logFilePath != "" {
		trimmed, err := openTrimmingLog(*logFilePath)
		if err != nil {
			rb := newRingLogBuffer(2000)
			globalLogBuf = rb
			logWriter = rb
		} else {
			logWriter = trimmed
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
	if lvl := os.Getenv("WHISPERA_LOG_LEVEL"); lvl != "" {
		log.SetLevel(logger.ParseLevel(lvl))
	}
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
