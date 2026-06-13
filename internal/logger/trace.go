package logger

import (
	"os"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	traceLogger *zap.SugaredLogger
	traceOnce   sync.Once
)

func Trace() *zap.SugaredLogger {
	traceOnce.Do(func() {
		encCfg := zap.NewProductionEncoderConfig()
		encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
		encCfg.TimeKey = "ts"
		encCfg.MessageKey = "event"
		core := zapcore.NewCore(
			zapcore.NewJSONEncoder(encCfg),
			zapcore.AddSync(os.Stdout),
			zapcore.InfoLevel,
		)
		traceLogger = zap.New(core, zap.AddCaller()).Named("tuntrace").Sugar()
	})
	return traceLogger
}
