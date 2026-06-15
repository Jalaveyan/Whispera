package neural

import (
	"os"
	"sync"
	"sync/atomic"
	"time"
	"whispera/neural/types"
)

var nativeEngine *NativeMLEngine
var globalDataCollector *DataCollector

func SetMLServerURL(url, token string) {
	if url != "" {
		os.Setenv("WHISPERA_ML_SERVER", url)
		if globalDataCollector != nil {
			globalDataCollector.SetMLServer(url, token)
		}
	}
}

func init() {
	modelDir := os.Getenv("WHISPERA_ML_MODEL_DIR")
	if modelDir == "" {
		modelDir = "./ml_models"
	}
	nativeEngine = NewNativeMLEngine(modelDir)

	dataDir := os.Getenv("WHISPERA_ML_DATA_DIR")
	if dataDir == "" {
		dataDir = "./ml_data"
	}
	globalDataCollector = NewDataCollector(10000, dataDir)
}

type NativeMLClientEvasionAdapter struct {
	engine      *NativeMLEngine
	flowCache   sync.Map
	sampleCount uint64
}

type nativeFlowProfile struct {
	dpiType    int
	confidence float64
	expires    time.Time
}

func (a *NativeMLClientEvasionAdapter) ProcessTraffic(data []byte, context *types.UnifiedTrafficContext) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	protocol := "tcp"
	direction := "outbound"
	if context != nil {
		if context.Protocol != "" {
			protocol = context.Protocol
		}
		if context.Direction != "" {
			direction = context.Direction
		}
	}

	key := protocol + ":" + direction

	if cached, ok := a.flowCache.Load(key); ok {
		fp := cached.(*nativeFlowProfile)
		if time.Now().Before(fp.expires) {
			return data, nil
		}
		a.flowCache.Delete(key)
	}

	atomic.AddUint64(&a.sampleCount, 1)

	if !a.engine.QualitySamplesReady() {
		a.engine.AddSample(data, 0, 0)
		return data, nil
	}

	resp := a.engine.Predict(data, protocol, direction)
	if resp == nil || len(resp.Predictions) == 0 {
		return data, nil
	}

	pred := resp.Predictions[0]
	a.engine.AddSample(data, pred.ClassID, pred.DPIType)

	fp := &nativeFlowProfile{
		dpiType:    pred.DPIType,
		confidence: pred.Confidence,
		expires:    time.Now().Add(30 * time.Second),
	}
	a.flowCache.Store(key, fp)

	if pred.DPIType > 0 && pred.Confidence > 0.5 {
		if sni := extractTLSSNI(data); sni != "" {
			a.engine.StoreSNI(sni)
		}
	}

	return data, nil
}

func (a *NativeMLClientEvasionAdapter) HealthCheck() error {
	return nil
}

func (a *NativeMLClientEvasionAdapter) LoadModels() error {
	return nil
}

func GetNativeEngine() *NativeMLEngine {
	return nativeEngine
}
