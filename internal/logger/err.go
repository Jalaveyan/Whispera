package logger

import (
	"os"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type errSyncer struct{}

func (errSyncer) Write(p []byte) (int, error) {
	l := Global()
	l.mu.Lock()
	w := l.config.Stderr
	l.mu.Unlock()
	if w == nil {
		w = os.Stderr
	}
	return w.Write(p)
}

func (errSyncer) Sync() error { return nil }

var (
	errLogger *zap.SugaredLogger
	errOnce   sync.Once
)

func Err() *zap.SugaredLogger {
	errOnce.Do(func() {
		encCfg := zap.NewProductionEncoderConfig()
		encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
		encCfg.TimeKey = "ts"
		encCfg.MessageKey = "msg"
		encCfg.LevelKey = "level"
		core := zapcore.NewCore(
			zapcore.NewConsoleEncoder(encCfg),
			zapcore.AddSync(errSyncer{}),
			zapcore.ErrorLevel,
		)
		errLogger = zap.New(core).Named("whispera").Sugar()
	})
	return errLogger
}
