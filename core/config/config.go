package config

import (
	"context"
	"fmt"
	"github.com/nekoskin/whispera/common/fsown"
	"github.com/nekoskin/whispera/common/runtime/base"
	"github.com/nekoskin/whispera/common/runtime/events"
	"github.com/nekoskin/whispera/common/runtime/interfaces"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	ModuleName    = "config.provider"
	ModuleVersion = "1.0.0"
)

type ServerConfig struct {
	Server      ServerSettings    `yaml:"server"`
	Transport   TransportConfig   `yaml:"transport"`
	Session     SessionConfig     `yaml:"session"`
	Routing     RoutingConfig     `yaml:"routing"`
	Obfuscation ObfuscationConfig `yaml:"obfuscation"`
	API         APIConfig         `yaml:"api"`
	Logging     LoggingConfig     `yaml:"logging"`
	Relay       RelayConfig       `yaml:"relay"`
	Whispera    WhisperaConfig    `yaml:"whispera"`
	GRPC        GRPCConfig        `yaml:"grpc" json:"grpc"`
	YaDisk      YaDiskConfig      `yaml:"yadisk" json:"yadisk"`
	Inbounds    []InboundConfig   `yaml:"inbounds" json:"inbounds"`
	Outbounds   []OutboundConfig  `yaml:"outbounds" json:"outbounds"`
	StealthMode string            `yaml:"stealth_mode" json:"stealth_mode"`
	Update      UpdateConfig      `yaml:"update" json:"update"`
}

type RelayConfig struct {
	EnableTCP     bool   `yaml:"enable_tcp"`
	EnableUDP     bool   `yaml:"enable_udp"`
	Debug         bool   `yaml:"debug"`
	UpstreamProxy string `yaml:"upstream_proxy"`
}

type UpdateConfig struct {
	Enabled       bool     `yaml:"enabled" json:"enabled"`
	ManifestURL   string   `yaml:"manifest_url" json:"manifest_url"`
	PublicKey     string   `yaml:"public_key" json:"public_key"`
	CheckInterval Duration `yaml:"check_interval" json:"check_interval"`
}

type OutboundConfig struct {
	Tag      string                 `yaml:"tag" json:"tag"`
	Address  string                 `yaml:"address" json:"address"`
	Settings map[string]interface{} `yaml:"settings" json:"settings"`
	Chain    []string               `yaml:"chain" json:"chain"`
}

type InboundConfig struct {
	Tag    string `yaml:"tag" json:"tag"`
	Listen string `yaml:"listen" json:"listen"`
	Port   int    `yaml:"port" json:"port"`
	Ports  []int  `yaml:"ports,omitempty" json:"ports,omitempty"`

	Mode       string `yaml:"mode,omitempty" json:"mode,omitempty"`
	RemoteAddr string `yaml:"remote_addr,omitempty" json:"remote_addr,omitempty"`

	Settings map[string]interface{} `yaml:"settings" json:"settings"`

	StreamSettings StreamConfig `yaml:"stream_settings" json:"stream_settings"`
}

type StreamConfig struct {
	Network  string                 `yaml:"network" json:"network"`
	Security string                 `yaml:"security" json:"security"`
	TLS      TLSConfig              `yaml:"tls" json:"tls"`
	WS       WebSocketConfig        `yaml:"ws" json:"ws"`
	Params   map[string]interface{} `yaml:"params,omitempty" json:"params,omitempty"`
}

type TLSConfig struct {
	CertFile string `yaml:"cert_file" json:"cert_file"`
	KeyFile  string `yaml:"key_file" json:"key_file"`
}

type WebSocketConfig struct {
	Path string `yaml:"path" json:"path"`
}

type H2CStreamConfig struct {
	Path string `yaml:"path" json:"path"`
}

type SniffingConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}

type WhisperaConfig struct {
	Enabled        bool   `yaml:"enabled" json:"enabled"`
	ListenAddr     string `yaml:"listen_addr" json:"listen_addr"`
	BackendH2CAddr string `yaml:"backend_h2c_addr" json:"backend_h2c_addr"`
	TLSCert        string `yaml:"tls_cert" json:"tls_cert"`
	TLSKey         string `yaml:"tls_key" json:"tls_key"`
	Domain         string `yaml:"domain" json:"domain"`
	ACMEDir        string `yaml:"acme_dir" json:"acme_dir"`
	DecoyOrigin    string `yaml:"decoy_origin" json:"decoy_origin"`
	Secret         string `yaml:"secret" json:"secret"`
	QUICListenAddr string `yaml:"quic_listen_addr" json:"quic_listen_addr"`
	ExtraPorts     []int  `yaml:"extra_ports,omitempty" json:"extra_ports,omitempty"`
	QUICExtraPorts []int  `yaml:"quic_extra_ports,omitempty" json:"quic_extra_ports,omitempty"`
}

type GRPCConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	ListenAddr string `yaml:"listen_addr" json:"listen_addr"`
	ServerName string `yaml:"server_name" json:"server_name"`
	TLSCert    string `yaml:"tls_cert" json:"tls_cert"`
	TLSKey     string `yaml:"tls_key" json:"tls_key"`
	ExtraPorts []int  `yaml:"extra_ports,omitempty" json:"extra_ports,omitempty"`
}

type YaDiskConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	OAuthToken string `yaml:"oauth_token" json:"oauth_token"`
	SessionID  string `yaml:"session_id" json:"session_id"`
}

type ServerSettings struct {
	Name         string   `yaml:"name" json:"name"`
	ListenAddr   string   `yaml:"listen_addr" json:"listen_addr"`
	MTU          int      `yaml:"mtu" json:"mtu"`
	Workers      int      `yaml:"workers" json:"workers"`
	GracefulStop Duration `yaml:"graceful_stop" json:"graceful_stop"`
	PrivateKey   string   `yaml:"private_key" json:"private_key"`
	PublicURL    string   `yaml:"public_url" json:"public_url"`
}

type TransportConfig struct {
	TCP struct {
		Enabled    bool   `yaml:"enabled"`
		ListenAddr string `yaml:"listen_addr"`
	} `yaml:"tcp"`
}

type SessionConfig struct {
	MaxSessions       int      `yaml:"max_sessions"`
	SessionTimeout    Duration `yaml:"session_timeout"`
	CleanupInterval   Duration `yaml:"cleanup_interval"`
	KeepaliveInterval Duration `yaml:"keepalive_interval"`
}

type RoutingConfig struct {
	Geo struct {
		Enabled        bool     `yaml:"enabled"`
		GeoIPFile      string   `yaml:"geoip_file"`
		GeoSiteFile    string   `yaml:"geosite_file"`
		UpdateInterval Duration `yaml:"update_interval"`
	} `yaml:"geo"`

	DNS struct {
		Enabled     bool   `yaml:"enabled"`
		Upstream    string `yaml:"upstream"`
		FakeIPRange string `yaml:"fakeip_range"`
	} `yaml:"dns"`
}

type ObfuscationConfig struct {
	Profile string `yaml:"profile"`
}

type APIConfig struct {
	Enabled        bool     `yaml:"enabled"`
	ListenAddr     string   `yaml:"listen_addr"`
	AuthToken      string   `yaml:"auth_token"`
	WebRoot        string   `yaml:"web_root"`
	EnableCORS     bool     `yaml:"enable_cors"`
	AllowedOrigins []string `yaml:"allowed_origins"`
	TLSCert        string   `yaml:"tls_cert"`
	TLSKey         string   `yaml:"tls_key"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Output string `yaml:"output"`
	File   string `yaml:"file"`
}

type Provider struct {
	*base.Module
	mu           sync.RWMutex
	config       *ServerConfig
	configPath   string
	watchers     map[string][]chan interface{}
	watchersMu   sync.RWMutex
	fileWatcher  chan struct{}
	lastModified time.Time
}

func New(configPath string) (*Provider, error) {
	p := &Provider{
		Module:      base.NewModule(ModuleName, ModuleVersion, nil),
		configPath:  configPath,
		config:      DefaultServerConfig(),
		watchers:    make(map[string][]chan interface{}),
		fileWatcher: make(chan struct{}),
	}

	return p, nil
}

type Duration time.Duration

func (d Duration) D() time.Duration { return time.Duration(d) }

func (d Duration) MarshalYAML() (interface{}, error) { return time.Duration(d).String(), nil }

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return &yaml.TypeError{Errors: []string{fmt.Sprintf("line %d: duration must be a scalar, keeping default", value.Line)}}
	}

	if n, err := strconv.ParseInt(value.Value, 10, 64); err == nil {
		*d = Duration(time.Duration(n) * time.Second)
		return nil
	}

	dur, err := time.ParseDuration(value.Value)
	if err != nil {
		return &yaml.TypeError{Errors: []string{fmt.Sprintf("line %d: cannot parse %q as duration (use integer seconds or '30s'), keeping default", value.Line, value.Value)}}
	}
	*d = Duration(dur)
	return nil
}

func (p *Provider) SaveConfig(path string) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.saveConfig(path)
}

func (p *Provider) saveConfig(path string) error {
	cfg := p.config

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if previous, err := os.ReadFile(path); err == nil {
		if err := os.WriteFile(path+".bak", previous, 0600); err != nil {
			log.Printf("[config] could not back up %s before overwrite: %v", path, err)
		}
	}

	if err := fsown.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	if err := p.UpdateChecksum(); err != nil {
		return fmt.Errorf("failed to update checksum: %w", err)
	}

	return nil
}

func (p *Provider) Update(fn func(*ServerConfig)) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	oldConfig := p.config
	newConfig := *p.config
	fn(&newConfig)
	p.config = &newConfig

	if p.configPath != "" {
		if err := p.saveConfig(p.configPath); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}
	}

	p.notifyChanges(oldConfig, p.config)

	return nil
}

func (p *Provider) watchConfigFile() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.fileWatcher:
			return
		case <-ticker.C:
			if p.configPath == "" {
				continue
			}

			info, err := os.Stat(p.configPath)
			if err != nil {
				continue
			}

			if info.ModTime().After(p.lastModified) {
				if err := p.VerifyIntegrity(); err != nil {
					p.AlertAndDie(fmt.Sprintf("Unauthorized configuration change detected! %v", err))
					return
				}

				if err := p.Reload(); err != nil {
					p.SetHealthy(false, fmt.Sprintf("reload error: %v", err))
				} else {
					p.lastModified = info.ModTime()
				}
			}
		}
	}
}

func (p *Provider) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := p.Module.Init(ctx, cfg); err != nil {
		return err
	}
	if p.configPath != "" {
		if err := p.Load(p.configPath); err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		if err := p.VerifyIntegrity(); err != nil {
			log.Printf("[config] Startup integrity mismatch — auto-repairing checksum: %v", err)
			_ = p.UpdateChecksum()
		}
	}

	return nil
}

func (p *Provider) Start() error {
	if err := p.Module.Start(); err != nil {
		return err
	}

	if p.configPath != "" {
		go p.watchConfigFile()
	}

	p.SetHealthy(true, "config provider running")
	p.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"config_path": p.configPath,
	})

	return nil
}

func (c *InboundConfig) AllPorts() []int {
	seen := make(map[int]struct{})
	var out []int
	for _, p := range append([]int{c.Port}, c.Ports...) {
		if p > 0 {
			if _, dup := seen[p]; !dup {
				seen[p] = struct{}{}
				out = append(out, p)
			}
		}
	}
	return out
}

func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Server: ServerSettings{
			Name:         "whispera-server",
			ListenAddr:   ":443",
			MTU:          1420,
			Workers:      8,
			GracefulStop: Duration(30 * time.Second),
		},
		Inbounds: []InboundConfig{
			{
				Tag:    "default-inbound",
				Listen: "0.0.0.0",
				Port:   8443,
				StreamSettings: StreamConfig{
					Network:  "tcp",
					Security: "none",
				},
			},
		},
		Session: SessionConfig{
			MaxSessions:       10000,
			SessionTimeout:    Duration(24 * time.Hour),
			CleanupInterval:   Duration(1 * time.Minute),
			KeepaliveInterval: Duration(30 * time.Second),
		},
		Routing: RoutingConfig{},
		Obfuscation: ObfuscationConfig{
			Profile: "default",
		},
		API: APIConfig{
			Enabled:    true,
			ListenAddr: ":8080",
			EnableCORS: true,
			WebRoot:    "",
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
			Output: "stdout",
		},
		Relay: RelayConfig{
			EnableTCP: true,
			EnableUDP: true,
			Debug:     false,
		},
	}
}

func (p *Provider) Stop() error {
	close(p.fileWatcher)

	p.watchersMu.Lock()
	for _, watchers := range p.watchers {
		for _, ch := range watchers {
			close(ch)
		}
	}
	p.watchers = nil
	p.watchersMu.Unlock()

	p.PublishEvent(events.EventTypeModuleStopped, nil)
	return p.Module.Stop()
}

func (p *Provider) Load(source string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	cfgPtr := DefaultServerConfig()
	cfg := *cfgPtr

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		te, ok := err.(*yaml.TypeError)
		if !ok {
			return fmt.Errorf("failed to parse config: %w", err)
		}
		for _, msg := range te.Errors {
			log.Printf("[config] %s: %s", source, msg)
		}
		return fmt.Errorf("failed to parse %s: %s (refusing to start on defaults — fix the file, settings would be overwritten)",
			source, strings.Join(te.Errors, "; "))
	}

	if err := cfg.fill(); err != nil {
		return fmt.Errorf("invalid config %s: %w", source, err)
	}

	p.mu.Lock()
	oldConfig := p.config
	p.config = &cfg
	p.configPath = source
	p.mu.Unlock()

	if info, err := os.Stat(source); err == nil {
		p.lastModified = info.ModTime()
	}
	p.notifyChanges(oldConfig, &cfg)

	return nil
}

func (p *Provider) Reload() error {
	if p.configPath == "" {
		return fmt.Errorf("no config path set")
	}

	if err := p.Load(p.configPath); err != nil {
		return err
	}

	p.PublishEvent(events.EventTypeConfigReloaded, map[string]interface{}{
		"config_path": p.configPath,
	})

	return nil
}

func (p *Provider) GetConfig() *ServerConfig {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.config
}

func (p *Provider) Get(key string) interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()
	switch key {
	case "server.listen_addr":
		return p.config.Server.ListenAddr
	case "server.mtu":
		return p.config.Server.MTU
	case "session.max_sessions":
		return p.config.Session.MaxSessions
	case "session.timeout":
		return p.config.Session.SessionTimeout.D()
	case "obfuscation.profile":
		return p.config.Obfuscation.Profile
	default:
		return nil
	}
}

func (p *Provider) GetString(key string) string {
	if v := p.Get(key); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func (p *Provider) GetInt(key string) int {
	if v := p.Get(key); v != nil {
		if i, ok := v.(int); ok {
			return i
		}
	}
	return 0
}

func (p *Provider) GetBool(key string) bool {
	if v := p.Get(key); v != nil {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func (p *Provider) GetDuration(key string) time.Duration {
	if v := p.Get(key); v != nil {
		if d, ok := v.(time.Duration); ok {
			return d
		}
	}
	return 0
}

func (p *Provider) Set(key string, value interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch key {
	case "server.listen_addr":
		if v, ok := value.(string); ok {
			p.config.Server.ListenAddr = v
		}
	case "server.mtu":
		if v, ok := value.(int); ok {
			p.config.Server.MTU = v
		}
	}

	p.notifyWatchers(key, value)
}

func (p *Provider) Watch(key string) <-chan interface{} {
	ch := make(chan interface{}, 10)

	p.watchersMu.Lock()
	p.watchers[key] = append(p.watchers[key], ch)
	p.watchersMu.Unlock()

	return ch
}

func (p *Provider) notifyWatchers(key string, value interface{}) {
	p.watchersMu.RLock()
	defer p.watchersMu.RUnlock()

	if watchers, ok := p.watchers[key]; ok {
		for _, ch := range watchers {
			select {
			case ch <- value:
			default:
			}
		}
	}
}

func (p *Provider) notifyChanges(old, new *ServerConfig) {
	if old == nil || new == nil {
		return
	}

	if old.Server.ListenAddr != new.Server.ListenAddr {
		p.notifyWatchers("server.listen_addr", new.Server.ListenAddr)
	}
	if old.Server.MTU != new.Server.MTU {
		p.notifyWatchers("server.mtu", new.Server.MTU)
	}
	if old.Session.MaxSessions != new.Session.MaxSessions {
		p.notifyWatchers("session.max_sessions", new.Session.MaxSessions)
	}
	if old.Obfuscation.Profile != new.Obfuscation.Profile {
		p.notifyWatchers("obfuscation.profile", new.Obfuscation.Profile)
	}
	if len(old.Outbounds) != len(new.Outbounds) {
		p.notifyWatchers("outbounds", new.Outbounds)
	}
}

func (p *Provider) GetConfigPath() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.configPath
}

func (p *Provider) Validate() error {
	p.mu.RLock()
	cfg := p.config
	p.mu.RUnlock()
	return cfg.validate()
}

func (c *ServerConfig) fill() error {
	d := DefaultServerConfig()

	if c.Server.ListenAddr == "" {
		c.Server.ListenAddr = d.Server.ListenAddr
	}
	if c.Server.MTU == 0 {
		c.Server.MTU = d.Server.MTU
	}
	if c.Server.Workers == 0 {
		c.Server.Workers = d.Server.Workers
	}
	if c.Server.GracefulStop == 0 {
		c.Server.GracefulStop = d.Server.GracefulStop
	}
	if c.Session.MaxSessions == 0 {
		c.Session.MaxSessions = d.Session.MaxSessions
	}

	fillDuration(&c.Server.GracefulStop, d.Server.GracefulStop)
	fillDuration(&c.Session.SessionTimeout, d.Session.SessionTimeout)
	fillDuration(&c.Session.CleanupInterval, d.Session.CleanupInterval)
	fillDuration(&c.Session.KeepaliveInterval, d.Session.KeepaliveInterval)

	return c.validate()
}

const maxSaneDuration = Duration(30 * 24 * time.Hour)

func fillDuration(v *Duration, fallback Duration) {
	if *v <= 0 || *v > maxSaneDuration {
		*v = fallback
	}
}

func (c *ServerConfig) validate() error {
	if c.Server.ListenAddr == "" {
		return fmt.Errorf("server.listen_addr is required")
	}
	if _, _, err := net.SplitHostPort(c.Server.ListenAddr); err != nil {
		return fmt.Errorf("server.listen_addr %q must be host:port: %w", c.Server.ListenAddr, err)
	}
	if c.Server.MTU < 576 || c.Server.MTU > 65535 {
		return fmt.Errorf("server.mtu is %d, must be between 576 and 65535", c.Server.MTU)
	}
	if c.Session.MaxSessions < 1 {
		return fmt.Errorf("session.max_sessions is %d, must be at least 1", c.Session.MaxSessions)
	}
	if c.Whispera.Enabled && c.Whispera.ListenAddr != "" {
		if _, _, err := net.SplitHostPort(c.Whispera.ListenAddr); err != nil {
			return fmt.Errorf("whispera.listen_addr %q must be host:port: %w", c.Whispera.ListenAddr, err)
		}
	}
	return nil
}

func HostFromPublicURL(publicURL string) string {
	if publicURL == "" {
		return ""
	}
	s := strings.TrimRight(strings.TrimPrefix(strings.TrimPrefix(publicURL, "https://"), "http://"), "/")
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return s
}

func PortFromListenAddr(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil {
		return port
	}
	return addr
}
