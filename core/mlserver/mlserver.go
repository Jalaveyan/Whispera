package mlserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/nekoskin/whispera/common/runtime/base"
	"github.com/nekoskin/whispera/common/runtime/interfaces"
	"github.com/nekoskin/whispera/common/runtime/registry"
	"github.com/nekoskin/whispera/neural"
	"github.com/nekoskin/whispera/neural/evasion"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

const (
	ModuleName    = "mlserver"
	ModuleVersion = "2.0.0"
)

type MLServer struct {
	*base.Module
	engine     *neural.NativeMLEngine
	httpServer *http.Server
	mux        *http.ServeMux
	listenAddr string
	tlsCert    string
	tlsKey     string
	token      string
	dataDir    string

	feedbackMu     sync.Mutex
	transportStats map[string]*TransportStats
	fedDir         string

	blockmapMu    sync.Mutex
	blockmap      map[string]*neural.BlockmapEntry
	ooniByCC      map[string]neural.OONIContext
	ooniCountries []string

	adversarial *evasion.AdversarialEngine

	logLines []string
	logMu    sync.Mutex
	maxLogs  int
}

type TransportStats struct {
	Success      int64   `json:"success"`
	Fail         int64   `json:"fail"`
	Total        int64   `json:"total"`
	TotalLatency float64 `json:"total_latency"`
	Count        int64   `json:"count"`
}

type Config struct {
	ListenAddr    string   `yaml:"listen_addr" json:"listen_addr"`
	TLSCert       string   `yaml:"tls_cert" json:"tls_cert"`
	TLSKey        string   `yaml:"tls_key" json:"tls_key"`
	Token         string   `yaml:"token" json:"token"`
	DataDir       string   `yaml:"data_dir" json:"data_dir"`
	ModelDir      string   `yaml:"model_dir" json:"model_dir"`
	OONICountries []string `yaml:"ooni_countries" json:"ooni_countries"`
}

func New(cfg interface{}) (*MLServer, error) {
	var conf Config
	if c, ok := cfg.(*Config); ok && c != nil {
		conf = *c
	}
	conf.ListenAddr = strings.TrimPrefix(conf.ListenAddr, "https://")
	conf.ListenAddr = strings.TrimPrefix(conf.ListenAddr, "http://")
	if conf.ListenAddr == "" {
		conf.ListenAddr = ":8000"
	}
	if conf.DataDir == "" {
		conf.DataDir = "./ml_data"
	}
	if conf.ModelDir == "" {
		conf.ModelDir = "./ml_models"
	}

	os.MkdirAll(conf.DataDir, 0700)

	s := &MLServer{
		Module:         base.NewModule(ModuleName, ModuleVersion, nil),
		engine:         neural.GetNativeEngine(),
		mux:            http.NewServeMux(),
		listenAddr:     conf.ListenAddr,
		tlsCert:        conf.TLSCert,
		tlsKey:         conf.TLSKey,
		token:          conf.Token,
		dataDir:        conf.DataDir,
		transportStats: make(map[string]*TransportStats),
		blockmap:       make(map[string]*neural.BlockmapEntry),
		ooniCountries:  conf.OONICountries,
		fedDir:         filepath.Join(conf.DataDir, "federated"),
		adversarial:    evasion.NewAdversarialEngine(),
		maxLogs:        1000,
	}

	if s.engine == nil {
		s.engine = neural.NewNativeMLEngine(conf.ModelDir)
	}

	os.MkdirAll(s.fedDir, 0700)
	s.registerRoutes()
	return s, nil
}

func (s *MLServer) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	return s.Module.Init(ctx, cfg)
}

func (s *MLServer) Adversarial() *evasion.AdversarialEngine {
	return s.adversarial
}

func (s *MLServer) Start() error {
	if err := s.Module.Start(); err != nil {
		return err
	}

	s.httpServer = &http.Server{
		Handler:      s.authMiddleware(s.mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("ml server listen: %w", err)
	}

	if s.tlsCert != "" && s.tlsKey != "" {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		cert, err := tls.LoadX509KeyPair(s.tlsCert, s.tlsKey)
		if err != nil {
			return fmt.Errorf("ml server tls load failed: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
		tlsLn := tls.NewListener(ln, tlsCfg)
		go func() {
			serveErr := s.httpServer.Serve(tlsLn)
			if serveErr != nil && serveErr != http.ErrServerClosed {
			}
		}()
		s.addLogf("ML server started on %s (HTTPS, native Go MLP engine)", s.listenAddr)
	} else {
		go func() {
			serveErr := s.httpServer.Serve(ln)
			if serveErr != nil && serveErr != http.ErrServerClosed {
			}
		}()
		s.addLogf("ML server started on %s (HTTP, native Go MLP engine)", s.listenAddr)
	}
	s.SetHealthy(true, "ml server running")
	return nil
}

func (s *MLServer) Stop() error {
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.httpServer.Shutdown(ctx)
	}
	return s.Module.Stop()
}

func (s *MLServer) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if s.token != "" {
			auth := r.Header.Get("Authorization")
			if auth != "" {
				parts := strings.SplitN(auth, " ", 2)
				if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") && parts[1] == s.token {
					next.ServeHTTP(w, r)
					return
				}
			}
			if r.URL.Path != "/health" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *MLServer) registerRoutes() {
	s.mux.HandleFunc("GET /health", s.handleHealth)
	s.mux.HandleFunc("GET /logs", s.handleLogs)
	s.mux.HandleFunc("POST /logs/clear", s.handleLogsClear)
	s.mux.HandleFunc("GET /models/status", s.handleModelsStatus)
	s.mux.HandleFunc("POST /models/load", s.handleModelsLoad)
	s.mux.HandleFunc("GET /self-learning/status", s.handleSelfLearningStatus)
	s.mux.HandleFunc("POST /predict/traffic", s.handlePredictTraffic)
	s.mux.HandleFunc("POST /network/analyze", s.handleNetworkAnalyze)
	s.mux.HandleFunc("POST /recommend/transport", s.handleRecommendTransport)
	s.mux.HandleFunc("POST /feedback/connection", s.handleFeedbackConnection)
	s.mux.HandleFunc("GET /feedback/stats", s.handleFeedbackStats)
	s.mux.HandleFunc("POST /train/start", s.handleTrainStart)
	s.mux.HandleFunc("POST /train/stop", s.handleTrainStop)
	s.mux.HandleFunc("GET /train/status", s.handleTrainStatus)
	s.mux.HandleFunc("GET /scan", s.handleScan)
	s.mux.HandleFunc("GET /selftest", s.handleSelfTest)
	s.mux.HandleFunc("GET /federated/export", s.handleFedExport)
	s.mux.HandleFunc("POST /federated/import", s.handleFedImport)
	s.mux.HandleFunc("GET /federated/status", s.handleFedStatus)
	s.mux.HandleFunc("GET /federated/losses", s.handleFedLosses)
	s.mux.HandleFunc("POST /federated/upload", s.handleFedUpload)
	s.mux.HandleFunc("GET /federated/download", s.handleFedDownload)
	s.mux.HandleFunc("POST /federated/blockreport", s.handleBlockReport)
	s.mux.HandleFunc("GET /federated/blockmap", s.handleBlockmap)
	s.loadBlockmap()
	if len(s.ooniCountries) == 0 {
		s.ooniCountries = []string{"RU"}
	}
	s.startOONIWorker(s.ooniCountries)
	s.mux.HandleFunc("GET /federated/dataset", s.handleFedDatasetExport)
	s.mux.HandleFunc("GET /federated/dataset/stats", s.handleFedDatasetStats)
	s.mux.HandleFunc("GET /datasets", s.handleDatasetsList)
	s.mux.HandleFunc("POST /datasets/capture", s.handleDatasetsCapture)
	s.mux.HandleFunc("POST /datasets/upload", s.handleDatasetsUpload)
	s.mux.HandleFunc("POST /datasets/exchange", s.handleDatasetsExchange)
	s.mux.HandleFunc("GET /adversarial/status", s.handleAdversarialStatus)
	s.mux.HandleFunc("POST /adversarial/evolve", s.handleAdversarialEvolve)
	s.mux.HandleFunc("POST /adversarial/feedback", s.handleAdversarialFeedback)

	s.mux.HandleFunc("GET /tspu/stats", s.handleTSPUStats)
	s.mux.HandleFunc("POST /tspu/rst", s.handleTSPURST)
	s.mux.HandleFunc("POST /tspu/bandwidth", s.handleTSPUBandwidth)
}

func (s *MLServer) jsonReply(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (s *MLServer) addLogf(format string, args ...interface{}) {
	line := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
	s.logMu.Lock()
	s.logLines = append(s.logLines, line)
	if len(s.logLines) > s.maxLogs {
		s.logLines = s.logLines[len(s.logLines)-s.maxLogs:]
	}
	s.logMu.Unlock()
}

func (s *MLServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.jsonReply(w, map[string]interface{}{
		"status":  "ok",
		"engine":  "native_mlp_go",
		"version": ModuleVersion,
	})
}

func Factory(cfg interface{}) (interfaces.Module, error) {
	return New(cfg)
}
