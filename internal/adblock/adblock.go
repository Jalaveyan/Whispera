package adblock

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

const dataFile = "/etc/whispera/adblock.json"

type Rule struct {
	ID      string `json:"id"`
	Domain  string `json:"domain"`
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
}

type Engine struct {
	mu      sync.RWMutex
	rules   map[string]*Rule // id → rule
	nextID  int
	blocked uint64 // atomic: total blocked connections
}

type persist struct {
	Rules  []*Rule `json:"rules"`
	NextID int     `json:"next_id"`
}

var Global = &Engine{
	rules: make(map[string]*Rule),
}

func init() {
	Global.Load()
}

func (e *Engine) Load() {
	data, err := os.ReadFile(dataFile)
	if err != nil {
		return
	}
	var p persist
	if err := json.Unmarshal(data, &p); err != nil {
		log.Printf("[adblock] failed to load: %v", err)
		return
	}
	e.mu.Lock()
	for _, r := range p.Rules {
		e.rules[r.ID] = r
	}
	if p.NextID > e.nextID {
		e.nextID = p.NextID
	}
	e.mu.Unlock()
	log.Printf("[adblock] loaded %d rules", len(p.Rules))
}

func (e *Engine) Save() {
	e.mu.RLock()
	list := make([]*Rule, 0, len(e.rules))
	for _, r := range e.rules {
		list = append(list, r)
	}
	nid := e.nextID
	e.mu.RUnlock()

	data, err := json.Marshal(persist{Rules: list, NextID: nid})
	if err != nil {
		log.Printf("[adblock] marshal error: %v", err)
		return
	}
	if err := os.WriteFile(dataFile, data, 0600); err != nil {
		log.Printf("[adblock] save error: %v", err)
	}
}

func (e *Engine) Add(domain, typ string) *Rule {
	if typ == "" {
		typ = "domain"
	}
	e.mu.Lock()
	e.nextID++
	id := fmt.Sprintf("%d", e.nextID)
	r := &Rule{ID: id, Domain: strings.ToLower(strings.TrimSpace(domain)), Type: typ, Enabled: true}
	e.rules[id] = r
	e.mu.Unlock()
	go e.Save()
	return r
}

func (e *Engine) Remove(id string) {
	e.mu.Lock()
	delete(e.rules, id)
	e.mu.Unlock()
	go e.Save()
}

func (e *Engine) List() []*Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]*Rule, 0, len(e.rules))
	for _, r := range e.rules {
		out = append(out, r)
	}
	return out
}

// IsBlocked checks addr (hostname or IP) against enabled rules.
// Supports exact match and wildcard prefix (*.example.com).
func (e *Engine) IsBlocked(addr string) bool {
	if addr == "" {
		return false
	}
	host := strings.ToLower(addr)
	// strip port if present
	if i := strings.LastIndex(host, ":"); i > 0 {
		if !strings.Contains(host[:i], "]") { // not IPv6
			host = host[:i]
		}
	}

	e.mu.RLock()
	matched := false
	for _, r := range e.rules {
		if !r.Enabled {
			continue
		}
		pat := strings.ToLower(r.Domain)
		if pat == host {
			matched = true
			break
		}
		if strings.HasPrefix(pat, "*.") {
			suffix := pat[1:] // ".example.com"
			if host == pat[2:] || strings.HasSuffix(host, suffix) {
				matched = true
				break
			}
		}
	}
	e.mu.RUnlock()
	if matched {
		atomic.AddUint64(&e.blocked, 1)
	}
	return matched
}

func (e *Engine) BlockedCount() int64 {
	return int64(atomic.LoadUint64(&e.blocked))
}
