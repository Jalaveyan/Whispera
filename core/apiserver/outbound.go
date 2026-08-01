package apiserver

import (
	"encoding/json"
	"fmt"
	config2 "github.com/nekoskin/whispera/core/config"
	"net/http"
	"time"
)

func (s *Server) getConfigProvider() (interface{}, error) {
	if s.registry == nil {
		return nil, fmt.Errorf("registry not available")
	}
	module, ok := s.registry.Get("config.provider")
	if !ok {
		return nil, fmt.Errorf("config provider not found")
	}
	return module, nil
}

func (s *Server) handleGetOutbounds(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	module, err := s.getConfigProvider()
	if err != nil {
		s.jsonError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	type ConfigProvider interface {
		GetConfig() *config2.ServerConfig
	}

	provider, ok := module.(ConfigProvider)
	if !ok {
		s.jsonError(w, http.StatusInternalServerError, "invalid config provider")
		return
	}

	cfg := provider.GetConfig()

	s.jsonOK(w, map[string]interface{}{
		"count":     len(cfg.Outbounds),
		"outbounds": cfg.Outbounds,
	})
}

func (s *Server) handleAddOutbound(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	module, err := s.getConfigProvider()
	if err != nil {
		s.jsonError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	type ConfigUpdater interface {
		Update(func(*config2.ServerConfig)) error
	}

	provider, ok := module.(ConfigUpdater)
	if !ok {
		s.jsonError(w, http.StatusInternalServerError, "config provider does not support updates")
		return
	}

	var req config2.OutboundConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	if req.Tag == "" {
		req.Tag = fmt.Sprintf("outbound_%d", time.Now().UnixNano())
	}

	err = provider.Update(func(cfg *config2.ServerConfig) {
		for _, out := range cfg.Outbounds {
			if out.Tag == req.Tag {
				return
			}
		}
		cfg.Outbounds = append(cfg.Outbounds, req)
	})

	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "Failed to save config: "+err.Error())
		return
	}

	s.jsonCreated(w, map[string]interface{}{
		"success":  true,
		"outbound": req,
	})
}

func (s *Server) handleDeleteOutbound(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	module, err := s.getConfigProvider()
	if err != nil {
		s.jsonError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	type ConfigUpdater interface {
		Update(func(*config2.ServerConfig)) error
	}

	provider, ok := module.(ConfigUpdater)
	if !ok {
		s.jsonError(w, http.StatusInternalServerError, "config provider does not support updates")
		return
	}

	var req struct {
		Tag string `json:"tag"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	err = provider.Update(func(cfg *config2.ServerConfig) {
		newOutbounds := make([]config2.OutboundConfig, 0, len(cfg.Outbounds))
		for _, out := range cfg.Outbounds {
			if out.Tag != req.Tag {
				newOutbounds = append(newOutbounds, out)
			}
		}
		cfg.Outbounds = newOutbounds
	})

	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "Failed to save config: "+err.Error())
		return
	}

	s.jsonOK(w, map[string]interface{}{"success": true})
}
