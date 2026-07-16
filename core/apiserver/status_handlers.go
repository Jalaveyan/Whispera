package apiserver

import (
	"context"
	"github.com/nekoskin/whispera/app/db"
	"github.com/nekoskin/whispera/common/stats"
	config2 "github.com/nekoskin/whispera/core/config"
	"net/http"
	"time"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := s.HealthCheck()
	allHealthy := health.Healthy

	response := map[string]interface{}{
		"status":  "ok",
		"healthy": health.Healthy,
		"message": health.Message,
		"uptime":  time.Since(s.startTime).String(),
	}

	deps := make(map[string]interface{})

	if database := db.Global(); database != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := database.Ping(ctx); err != nil {
			deps["database"] = map[string]interface{}{"status": "unhealthy", "error": err.Error()}
			allHealthy = false
		} else {
			deps["database"] = map[string]interface{}{"status": "healthy"}
		}
	} else {
		deps["database"] = map[string]interface{}{"status": "disabled"}
	}

	if s.registry != nil {
		moduleHealth := s.registry.HealthCheck()
		response["modules"] = moduleHealth
		for _, mh := range moduleHealth {
			if !mh.Healthy {
				allHealthy = false
			}
		}
	}

	response["dependencies"] = deps
	response["healthy"] = allHealthy

	if !allHealthy {
		response["status"] = "degraded"
	}

	s.jsonOK(w, response)
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	status := map[string]interface{}{
		"version": ModuleVersion,
		"uptime":  time.Since(s.LastActivity()).String(),
		"running": s.IsRunning(),
	}

	if s.registry != nil {
		modules := s.registry.GetAll()
		status["module_count"] = len(modules)
	}

	s.jsonOK(w, status)
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	resp := map[string]interface{}{
		"api": map[string]interface{}{
			"listen_addr": s.config.ListenAddr,
			"cors":        s.config.EnableCORS,
		},
	}

	if s.registry != nil {
		if module, ok := s.registry.Get("config.provider"); ok {
			if cfgProvider, ok := module.(*config2.Provider); ok {
				cfg := cfgProvider.GetConfig()
				resp["stealth_mode"] = cfg.StealthMode
				resp["public_url"] = cfg.Server.PublicURL
			}
		}
	}

	s.jsonOK(w, resp)
}

func (s *Server) handleTrafficStats(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	globalStats := stats.GetGlobalStats()

	s.jsonOK(w, map[string]interface{}{
		"total_download":   globalStats.TotalBytesRx,
		"total_upload":     globalStats.TotalBytesTx,
		"total_packets_rx": globalStats.TotalPacketsRx,
		"total_packets_tx": globalStats.TotalPacketsTx,
		"active_users":     globalStats.ActiveUsers,
		"uptime":           globalStats.Uptime,
		"uptime_seconds":   globalStats.UptimeSeconds,
		"history":          globalStats.History,
	})
}
