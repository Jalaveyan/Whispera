package dns

import (
	"context"
	"fmt"
	"github.com/nekoskin/whispera/common/cache"
	"github.com/nekoskin/whispera/common/runtime/base"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ModuleName    = "dns.resolver"
	ModuleVersion = "1.0.0"

	DefaultCacheSize = 10000
	DefaultCacheTTL  = 5 * time.Minute
)

type Config struct {
	Upstream        string
	FakeIPEnabled   bool
	FakeIPRange     string
	CacheEnabled    bool
	CacheSize       int
	CacheTTL        time.Duration
	BlockingEnabled bool
	BlockLists      []string
	DialContext     func(ctx context.Context, network, address string) (net.Conn, error)
	BypassFunc      func(hostname string) bool
	BypassResolver  *net.Resolver
}

// pending is one upstream query others can wait on, so a page opening twenty
// streams to the same host asks once instead of twenty times.
type pending struct {
	done chan struct{}
	ips  []net.IP
	err  error
}

type Resolver struct {
	*base.Module
	config     *Config
	cache      *cache.LRUCache[[]net.IP]
	upstreamMu sync.RWMutex
	dialCtx    func(ctx context.Context, network, address string) (net.Conn, error)
	dialCtxMu  sync.RWMutex

	inflightMu sync.Mutex
	inflight   map[string]*pending

	fakeIPNet     *net.IPNet
	fakeIPNext    uint32
	fakeIPMu      sync.Mutex
	fakeIPMap     map[string]net.IP
	fakeIPReverse map[string]string

	blockList   map[string]bool
	blockListMu sync.RWMutex

	queries     uint64
	cacheHits   uint64
	cacheMisses uint64
	blocked     uint64
	errors      uint64
}

func DefaultConfig() *Config {
	return &Config{
		Upstream:        "8.8.8.8:53",
		FakeIPEnabled:   false,
		FakeIPRange:     "198.18.0.0/15",
		CacheEnabled:    true,
		CacheSize:       DefaultCacheSize,
		CacheTTL:        DefaultCacheTTL,
		BlockingEnabled: false,
	}
}

func (c *Config) Validate() error {
	if c.CacheSize <= 0 {
		c.CacheSize = DefaultCacheSize
	}
	if c.CacheTTL <= 0 {
		c.CacheTTL = DefaultCacheTTL
	}
	return nil
}

func New(cfg *Config) (*Resolver, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	r := &Resolver{
		Module:        base.NewModule(ModuleName, ModuleVersion, nil),
		config:        cfg,
		cache:         cache.NewLRUCache[[]net.IP](cfg.CacheSize),
		fakeIPMap:     make(map[string]net.IP),
		fakeIPReverse: make(map[string]string),
		blockList:     make(map[string]bool),
	}

	if cfg.FakeIPEnabled {
		_, ipnet, err := net.ParseCIDR(cfg.FakeIPRange)
		if err == nil {
			r.fakeIPNet = ipnet
		}
	}

	return r, nil
}

func NewResolver(cfg *Config) *Resolver {
	r, _ := New(cfg)
	return r
}

func (r *Resolver) Resolve(ctx context.Context, domain string) ([]net.IP, error) {
	if ip := net.ParseIP(domain); ip != nil {
		return []net.IP{ip}, nil
	}
	atomic.AddUint64(&r.queries, 1)
	r.UpdateActivity()
	if r.isBlocked(domain) {
		atomic.AddUint64(&r.blocked, 1)
		return nil, fmt.Errorf("domain blocked: %s", domain)
	}

	if r.config.BypassFunc != nil && r.config.BypassFunc(domain) {
		resolver := r.config.BypassResolver
		if resolver == nil {
			resolver = net.DefaultResolver
		}
		addrs, err := resolver.LookupIPAddr(ctx, domain)
		if err != nil {
			return nil, err
		}
		ips := make([]net.IP, 0, len(addrs))
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
		return ips, nil
	}

	if r.config.CacheEnabled {
		if ips, _ := r.cache.Get(ctx, domain); ips != nil {
			atomic.AddUint64(&r.cacheHits, 1)
			return ips, nil
		}
		atomic.AddUint64(&r.cacheMisses, 1)
	}

	if r.config.FakeIPEnabled {
		ip := r.getFakeIP(domain)
		return []net.IP{ip}, nil
	}

	ips, err := r.resolveShared(ctx, domain)
	if err != nil {
		atomic.AddUint64(&r.errors, 1)
		return nil, err
	}

	return ips, nil
}

// resolveShared runs one upstream query per domain at a time; everyone else
// waits for it and takes the same answer.
func (r *Resolver) resolveShared(ctx context.Context, domain string) ([]net.IP, error) {
	r.inflightMu.Lock()
	if r.inflight == nil {
		r.inflight = make(map[string]*pending)
	}
	if p, ok := r.inflight[domain]; ok {
		r.inflightMu.Unlock()
		select {
		case <-p.done:
			return p.ips, p.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	p := &pending{done: make(chan struct{})}
	r.inflight[domain] = p
	r.inflightMu.Unlock()

	p.ips, p.err = r.resolveUpstream(ctx, domain)
	if p.err == nil && r.config.CacheEnabled && len(p.ips) > 0 {
		_ = r.cache.Set(ctx, domain, p.ips, r.config.CacheTTL)
	}

	r.inflightMu.Lock()
	delete(r.inflight, domain)
	r.inflightMu.Unlock()
	close(p.done)

	return p.ips, p.err
}

func (r *Resolver) ResolveUpstream(ctx context.Context, domain string) ([]net.IP, error) {
	if ip := net.ParseIP(domain); ip != nil {
		return []net.IP{ip}, nil
	}
	if r.config.CacheEnabled {
		if ips, _ := r.cache.Get(ctx, domain); ips != nil {
			return ips, nil
		}
	}
	return r.resolveShared(ctx, domain)
}

func (r *Resolver) SetDialContext(dialFn func(ctx context.Context, network, address string) (net.Conn, error)) {
	r.dialCtxMu.Lock()
	r.dialCtx = dialFn
	r.dialCtxMu.Unlock()
}

func (r *Resolver) SetUpstream(upstream string) {
	if strings.EqualFold(upstream, "system") {
		upstream = ""
	}
	r.upstreamMu.Lock()
	r.config.Upstream = upstream
	r.upstreamMu.Unlock()
	r.cache.Clear()
}

func (r *Resolver) GetUpstream() string {
	r.upstreamMu.RLock()
	defer r.upstreamMu.RUnlock()
	return r.config.Upstream
}

func (r *Resolver) isBlocked(domain string) bool {
	if !r.config.BlockingEnabled {
		return false
	}
	r.blockListMu.RLock()
	defer r.blockListMu.RUnlock()
	if r.blockList[domain] {
		return true
	}
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			if r.blockList[domain[i+1:]] {
				return true
			}
		}
	}
	return false
}

func (r *Resolver) getFakeIP(domain string) net.IP {
	r.fakeIPMu.Lock()
	defer r.fakeIPMu.Unlock()
	if ip, ok := r.fakeIPMap[domain]; ok {
		return ip
	}
	if r.fakeIPNet == nil {
		return net.ParseIP("198.18.0.1")
	}
	baseIP := r.fakeIPNet.IP.To4()
	if baseIP == nil {
		return net.ParseIP("198.18.0.1")
	}
	r.fakeIPNext++
	ip := make(net.IP, 4)
	copy(ip, baseIP)
	offset := r.fakeIPNext
	ip[3] = byte(offset)
	ip[2] = byte(offset >> 8)
	r.fakeIPMap[domain] = ip
	r.fakeIPReverse[ip.String()] = domain
	return ip
}
