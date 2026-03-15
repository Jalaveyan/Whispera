package logger

import (
	"fmt"
	"io"
	"os"
	"runtime"
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
	MaskLogs    bool // Enable fake (masked) logs
}

func DefaultConfig() *Config {
	mask := os.Getenv("WHISPERA_MASK_LOGS") == "false"
	return &Config{
		Level:       LevelInfo,
		EnableColor: true,
		Prefix:      "[WHISPERA]",
		ShowCaller:  false,
		TimeFormat:  "2006-01-02 15:04:05",
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		MaskLogs:    mask,
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
	if level < l.config.Level {
		return
	}

	// l.mu.Lock()
	// defer l.mu.Unlock()

	// if l.config.MaskLogs {
	// 	if level >= LevelError {
	// 		fmt.Fprint(l.config.Stdout, fakeErrorLog())
	// 	} else {
	// 		fmt.Fprint(l.config.Stdout, fakeNginxLog())
	// 	}
	// 	return
	// }

	var out io.Writer
	if level >= LevelError {
		out = l.config.Stderr
	} else {
		out = l.config.Stdout
	}

	var sb strings.Builder

	timestamp := time.Now().Format(l.config.TimeFormat)

	colorReset := "\033[0m"
	if l.config.EnableColor {
		sb.WriteString(level.Color())
	}

	if l.config.Prefix != "" {
		sb.WriteString(l.config.Prefix)
		sb.WriteString(" ")
	}

	sb.WriteString(fmt.Sprintf("[%s] [%s] ", timestamp, level.String()))

	if l.config.ShowCaller {
		_, file, line, ok := runtime.Caller(2)
		if ok {
			parts := strings.Split(file, "/")
			if len(parts) > 0 {
				file = parts[len(parts)-1]
			}
			sb.WriteString(fmt.Sprintf("(%s:%d) ", file, line))
		}
	}

	if len(args) > 0 {
		sb.WriteString(fmt.Sprintf(msg, args...))
	} else {
		sb.WriteString(msg)
	}

	if len(l.fields) > 0 {
		sb.WriteString(" |")
		for k, v := range l.fields {
			sb.WriteString(fmt.Sprintf(" %s=%v", k, v))
		}
	}

	if l.config.EnableColor {
		sb.WriteString(colorReset)
	}

	sb.WriteString("\n")

	fmt.Fprint(out, sb.String())
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

func SetGlobal(l *Logger) {
	globalLogger = l
}

func Debug(msg string, args ...interface{}) {
	Global().Debug(msg, args...)
}

func Info(msg string, args ...interface{}) {
	Global().Info(msg, args...)
}

func Warn(msg string, args ...interface{}) {
	Global().Warn(msg, args...)
}

func Error(msg string, args ...interface{}) {
	Global().Error(msg, args...)
}

func Fatal(msg string, args ...interface{}) {
	Global().Fatal(msg, args...)
}

func WithField(key string, value interface{}) *Logger {
	return Global().WithField(key, value)
}

func WithFields(fields map[string]interface{}) *Logger {
	return Global().WithFields(fields)
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
