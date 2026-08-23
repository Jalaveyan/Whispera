package apiserver

import (
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

	if provider, ok := configProviderAs[*config2.Provider](s); ok {
		cfg := provider.GetConfig()
		resp["stealth_mode"] = cfg.StealthMode
		resp["public_url"] = cfg.Server.PublicURL
	}

	s.jsonOK(w, resp)
}
