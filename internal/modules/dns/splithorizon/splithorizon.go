package splithorizon

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/logger"
)

var log = logger.Module("splithorizon")

const (
	ModuleName    = "dns.splithorizon"
	ModuleVersion = "1.0.0"
)

type View struct {
	Name        string
	Description string
	SourceNets   []*net.IPNet
	SourceIPs    []net.IP
	Domains      []string
	DomainSuffix []string

	Upstreams []string
	Records map[string][]Record

	Priority    int
	Recursion   bool
	DNSSEC      bool
	CacheMaxTTL time.Duration
}

type Record struct {
	Type  string
	Name  string
	Value string
	TTL   uint32
	Priority uint16
	Weight   uint16
	Port     uint16
}
type Config struct {
	Views []*View
	DefaultView *View

	EnableCache bool
	CacheTTL    time.Duration
	CacheSize   int

	LogQueries bool
}
func DefaultConfig() *Config {
	return &Config{
		Views:       make([]*View, 0),
		EnableCache: true,
		CacheTTL:    5 * time.Minute,
		CacheSize:   10000,
		LogQueries:  false,
		DefaultView: &View{
			Name:      "default",
			Upstreams: []string{"8.8.8.8:53", "1.1.1.1:53"},
			Recursion: true,
		},
	}
}

type Handler struct {
	*base.Module
	config *Config

	mu    sync.RWMutex
	views []*View
	cache *dnsCache

	totalQueries uint64
	viewHits     map[string]*uint64
	cacheHits    uint64
	cacheMisses  uint64
}

type dnsCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	maxSize int
}

type cacheEntry struct {
	response  []byte
	view      string
	expiresAt time.Time
}

func newDNSCache(size int) *dnsCache {
	return &dnsCache{
		entries: make(map[string]*cacheEntry),
		maxSize: size,
	}
}

func (c *dnsCache) get(key string) ([]byte, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.response, true
}

func (c *dnsCache) set(key string, response []byte, view string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.maxSize {
		now := time.Now()
		for k, v := range c.entries {
			if now.After(v.expiresAt) {
				delete(c.entries, k)
			}
		}
		for k := range c.entries {
			if len(c.entries) < c.maxSize {
				break
			}
			delete(c.entries, k)
		}
	}

	c.entries[key] = &cacheEntry{
		response:  response,
		view:      view,
		expiresAt: time.Now().Add(ttl),
	}
}

func New(cfg *Config) (*Handler, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	h := &Handler{
		Module:   base.NewModule(ModuleName, ModuleVersion, nil),
		config:   cfg,
		views:    cfg.Views,
		viewHits: make(map[string]*uint64),
	}

	if cfg.EnableCache {
		h.cache = newDNSCache(cfg.CacheSize)
	}

	for _, v := range cfg.Views {
		counter := uint64(0)
		h.viewHits[v.Name] = &counter
	}
	if cfg.DefaultView != nil {
		counter := uint64(0)
		h.viewHits[cfg.DefaultView.Name] = &counter
	}

	return h, nil
}

func (h *Handler) HandleQuery(ctx context.Context, clientIP net.IP, query []byte) ([]byte, error) {
	atomic.AddUint64(&h.totalQueries, 1)

	domain := extractDomainFromQuery(query)

	cacheKey := makeCacheKey(clientIP, domain)
	if h.cache != nil {
		if response, ok := h.cache.get(cacheKey); ok {
			atomic.AddUint64(&h.cacheHits, 1)
			return response, nil
		}
		atomic.AddUint64(&h.cacheMisses, 1)
	}

	view := h.selectView(clientIP, domain)

	if h.config.LogQueries {
		log.Debug("Query from %s for %s -> view: %s", clientIP, domain, view.Name)
	}

	if counter, ok := h.viewHits[view.Name]; ok {
		atomic.AddUint64(counter, 1)
	}

	if record := h.getStaticRecord(view, domain); record != nil {
		response := buildDNSResponse(query, record)
		if h.cache != nil {
			h.cache.set(cacheKey, response, view.Name, h.config.CacheTTL)
		}
		return response, nil
	}

	response, err := h.forwardQuery(view, query)
	if err != nil {
		return nil, err
	}
	if h.cache != nil {
		h.cache.set(cacheKey, response, view.Name, h.config.CacheTTL)
	}

	return response, nil
}

func (h *Handler) selectView(clientIP net.IP, domain string) *View {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, view := range h.views {
		if h.matchView(view, clientIP, domain) {
			return view
		}
	}

	return h.config.DefaultView
}

func (h *Handler) matchView(view *View, clientIP net.IP, domain string) bool {
	ipMatch := len(view.SourceNets) == 0 && len(view.SourceIPs) == 0

	for _, network := range view.SourceNets {
		if network.Contains(clientIP) {
			ipMatch = true
			break
		}
	}

	for _, ip := range view.SourceIPs {
		if ip.Equal(clientIP) {
			ipMatch = true
			break
		}
	}

	if !ipMatch {
		return false
	}

	domainMatch := len(view.Domains) == 0 && len(view.DomainSuffix) == 0

	for _, d := range view.Domains {
		if strings.EqualFold(domain, d) {
			domainMatch = true
			break
		}
	}

	for _, suffix := range view.DomainSuffix {
		if strings.HasSuffix(strings.ToLower(domain), strings.ToLower(suffix)) {
			domainMatch = true
			break
		}
	}

	return domainMatch
}

func (h *Handler) getStaticRecord(view *View, domain string) *Record {
	if view.Records == nil {
		return nil
	}

	records, ok := view.Records[strings.ToLower(domain)]
	if !ok || len(records) == 0 {
		return nil
	}

	return &records[0]
}

func (h *Handler) forwardQuery(view *View, query []byte) ([]byte, error) {
	upstreams := make([]string, 0, len(view.Upstreams))
	upstreams = append(upstreams, view.Upstreams...)

	if h.config.DefaultView != nil && view != h.config.DefaultView {
		upstreams = append(upstreams, h.config.DefaultView.Upstreams...)
	}

	if len(upstreams) == 0 {
		return nil, fmt.Errorf("no upstreams configured")
	}

	type result struct {
		response []byte
		err      error
	}
	resultCh := make(chan result, len(upstreams))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, upstream := range upstreams {
		go func(server string) {
			select {
			case <-ctx.Done():
				return
			default:
			}

			response, err := h.sendQuery(server, query)
			if err == nil {
				select {
				case resultCh <- result{response: response}:
				default:
				}
			}
		}(upstream)
	}

	select {
	case res := <-resultCh:
		return res.response, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("all upstreams failed or timed out")
	}
}

func (h *Handler) sendQuery(server string, query []byte) ([]byte, error) {
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	return response[:n], nil
}

func extractDomainFromQuery(query []byte) string {
	if len(query) < 12 {
		return ""
	}
	pos := 12
	var domain strings.Builder

	for pos < len(query) {
		length := int(query[pos])
		if length == 0 {
			break
		}
		if pos+length+1 > len(query) {
			break
		}
		if domain.Len() > 0 {
			domain.WriteByte('.')
		}
		domain.Write(query[pos+1 : pos+1+length])
		pos += length + 1
	}

	return domain.String()
}

func makeCacheKey(clientIP net.IP, domain string) string {
	return clientIP.String() + ":" + strings.ToLower(domain)
}

func buildDNSResponse(query []byte, record *Record) []byte {
	response := make([]byte, len(query))
	copy(response, query)
	response[2] = 0x81
	response[3] = 0x80

	response[6] = 0x00
	response[7] = 0x01

	switch record.Type {
	case "A":
		ip := net.ParseIP(record.Value).To4()
		if ip != nil {
			response = append(response, 0xC0, 0x0C)
			response = append(response, 0x00, 0x01)
			response = append(response, 0x00, 0x01)
			ttl := record.TTL
			if ttl == 0 {
				ttl = 300
			}
			response = append(response,
				byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl))
			response = append(response, 0x00, 0x04)
			response = append(response, ip...)
		}
	case "AAAA":
		ip := net.ParseIP(record.Value).To16()
		if ip != nil {
			response = append(response, 0xC0, 0x0C)
			response = append(response, 0x00, 0x1C)
			response = append(response, 0x00, 0x01)
			ttl := record.TTL
			if ttl == 0 {
				ttl = 300
			}
			response = append(response,
				byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl))
			response = append(response, 0x00, 0x10)
			response = append(response, ip...)
		}
	}

	return response
}

func (h *Handler) AddView(view *View) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.views = append(h.views, view)
	counter := uint64(0)
	h.viewHits[view.Name] = &counter

	for i := len(h.views) - 1; i > 0; i-- {
		if h.views[i].Priority < h.views[i-1].Priority {
			h.views[i], h.views[i-1] = h.views[i-1], h.views[i]
		}
	}
}

func (h *Handler) RemoveView(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for i, v := range h.views {
		if v.Name == name {
			h.views = append(h.views[:i], h.views[i+1:]...)
			delete(h.viewHits, name)
			break
		}
	}
}

func NewInternalView(name string, networks []string, upstreams []string) *View {
	nets := make([]*net.IPNet, 0, len(networks))
	for _, n := range networks {
		_, network, err := net.ParseCIDR(n)
		if err == nil {
			nets = append(nets, network)
		}
	}

	return &View{
		Name:       name,
		SourceNets: nets,
		Upstreams:  upstreams,
		Recursion:  true,
		Priority:   10,
	}
}

func NewExternalView(name string, upstreams []string) *View {
	return &View{
		Name:      name,
		Upstreams: upstreams,
		Recursion: true,
		Priority:  100,
	}
}

func NewBlockingView(name string, domains []string) *View {
	records := make(map[string][]Record)
	for _, domain := range domains {
		records[strings.ToLower(domain)] = []Record{
			{Type: "A", Name: domain, Value: "0.0.0.0", TTL: 3600},
		}
	}

	return &View{
		Name:     name,
		Domains:  domains,
		Records:  records,
		Priority: 1,
	}
}

func (h *Handler) Init(ctx context.Context) error {
	return nil
}

func (h *Handler) Start(ctx context.Context) error {
	return nil
}

func (h *Handler) Stop(ctx context.Context) error {
	return nil
}

func (h *Handler) Stats() map[string]interface{} {
	viewStats := make(map[string]uint64)
	for name, counter := range h.viewHits {
		viewStats[name] = atomic.LoadUint64(counter)
	}

	return map[string]interface{}{
		"total_queries": atomic.LoadUint64(&h.totalQueries),
		"cache_hits":    atomic.LoadUint64(&h.cacheHits),
		"cache_misses":  atomic.LoadUint64(&h.cacheMisses),
		"view_hits":     viewStats,
		"views_count":   len(h.views),
	}
}
