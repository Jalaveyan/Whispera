package logger

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	case LevelFatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

func (l Level) Color() string {
	switch l {
	case LevelDebug:
		return "\033[36m"
	case LevelInfo:
		return "\033[32m"
	case LevelWarn:
		return "\033[33m"
	case LevelError:
		return "\033[31m"
	case LevelFatal:
		return "\033[35m"
	default:
		return "\033[0m"
	}
}

type Config struct {
	Level       Level
	EnableColor bool
	Prefix      string
	ShowCaller  bool
	TimeFormat  string
	Stdout      io.Writer
	Stderr      io.Writer
	MaskLogs    bool
	JSONMode    bool
}

func DefaultConfig() *Config {
	mask := os.Getenv("WHISPERA_MASK_LOGS") == "false"
	jsonMode := os.Getenv("WHISPERA_LOG_JSON") == "true"
	return &Config{
		Level:       LevelInfo,
		EnableColor: !jsonMode,
		Prefix:      "[WHISPERA]",
		ShowCaller:  false,
		TimeFormat:  "2006-01-02 15:04:05",
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		MaskLogs:    mask,
		JSONMode:    jsonMode,
	}
}

type Logger struct {
	mu     sync.Mutex
	config *Config
	fields map[string]interface{}
}

func New(cfg *Config) *Logger {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if cfg.Stdout == nil {
		cfg.Stdout = os.Stdout
	}
	if cfg.Stderr == nil {
		cfg.Stderr = os.Stderr
	}
	if cfg.TimeFormat == "" {
		cfg.TimeFormat = "2006-01-02 15:04:05"
	}

	return &Logger{
		config: cfg,
		fields: make(map[string]interface{}),
	}
}

func (l *Logger) WithField(key string, value interface{}) *Logger {
	newLogger := &Logger{
		config: l.config,
		fields: make(map[string]interface{}),
	}
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}
	newLogger.fields[key] = value
	return newLogger
}

func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	newLogger := &Logger{
		config: l.config,
		fields: make(map[string]interface{}),
	}
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}
	for k, v := range fields {
		newLogger.fields[k] = v
	}
	return newLogger
}

func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.config.Level = level
}

func (l *Logger) GetLevel() Level {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.config.Level
}

// -----------------------------------------------------------------------------

func (l *Logger) log(level Level, msg string, args ...interface{}) {
	if level < LevelError {
		return
	}

	var formatted string
	if len(args) > 0 {
		formatted = fmt.Sprintf(msg, args...)
	} else {
		formatted = msg
	}

	now := time.Now()
	modName := ""
	if mod, ok := l.fields["module"]; ok {
		modName = fmt.Sprintf("%v", mod)
	}
	ring().push(RingEntry{
		Time:    now,
		Level:   level.String(),
		Module:  modName,
		Message: formatted,
	})

	z := Err()
	if len(l.fields) > 0 {
		kv := make([]interface{}, 0, len(l.fields)*2)
		for k, v := range l.fields {
			kv = append(kv, k, v)
		}
		z = z.With(kv...)
	}

	if level >= LevelFatal {
		z.Fatal(formatted)
		return
	}
	z.Error(formatted)
}

func (l *Logger) Debug(msg string, args ...interface{}) {
	l.log(LevelDebug, msg, args...)
}

func (l *Logger) Info(msg string, args ...interface{}) {
	l.log(LevelInfo, msg, args...)
}

func (l *Logger) Warn(msg string, args ...interface{}) {
	l.log(LevelWarn, msg, args...)
}

func (l *Logger) Error(msg string, args ...interface{}) {
	l.log(LevelError, msg, args...)
}

func (l *Logger) Fatal(msg string, args ...interface{}) {
	l.log(LevelFatal, msg, args...)
	os.Exit(1)
}

func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.log(LevelFatal, format, args...)
	os.Exit(1)
}

func (l *Logger) Printf(format string, args ...interface{}) {
	l.Info(format, args...)
}

func (l *Logger) Println(args ...interface{}) {
	l.Info("%s", fmt.Sprint(args...))
}

var (
	globalLogger     *Logger
	globalLoggerOnce sync.Once
)

func Global() *Logger {
	globalLoggerOnce.Do(func() {
		globalLogger = New(nil)
	})
	return globalLogger
}

func Warn(msg string, args ...interface{}) {
	Global().Warn(msg, args...)
}

func SetLevel(level Level) {
	Global().SetLevel(level)
}

func ParseLevel(s string) Level {
	switch strings.ToLower(s) {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	case "fatal":
		return LevelFatal
	default:
		return LevelInfo
	}
}

func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.config.Stdout = w
	l.config.Stderr = w
}

func SetOutput(w io.Writer) {
	Global().SetOutput(w)
}

func Module(name string) *Logger {
	return Global().WithField("module", name)
}
