package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type ClientConfig struct {
	Server           string `yaml:"server" json:"server"`
	ServerTCP        string `yaml:"server_tcp" json:"server_tcp"`
	ServerWS         string `yaml:"server_ws" json:"server_ws"`
	WhisperaAddr     string `yaml:"whispera_addr" json:"whispera_addr"`
	WhisperaSNI      string `yaml:"whispera_sni" json:"whispera_sni"`
	WhisperaCertPin  string `yaml:"whispera_cert_pin" json:"whispera_cert_pin"`
	WhisperaIDPub    string `yaml:"whispera_idpub" json:"whispera_idpub"`
	WhisperaSelPub   string `yaml:"whispera_selpub" json:"whispera_selpub"`
	WhisperaFPRaw    string `yaml:"tls_fp_raw" json:"tls_fp_raw"`
	WhisperaQUICAddr string `yaml:"whispera_quic_addr" json:"whispera_quic_addr"`
	GRPCAddr         string `yaml:"grpc_addr" json:"grpc_addr"`
	GRPCServerName   string `yaml:"grpc_server_name" json:"grpc_server_name"`
	GRPCUseTLS       bool   `yaml:"grpc_use_tls" json:"grpc_use_tls"`
	YaDiskOAuthToken string `yaml:"yadisk_oauth_token" json:"yadisk_oauth_token"`
	YaDiskSessionID  string `yaml:"yadisk_session_id" json:"yadisk_session_id"`
	ServerPub        string `yaml:"server_pub" json:"server_pub"`
	PSK              string `yaml:"psk" json:"psk"`

	SplitTunnel      bool   `yaml:"split_tunnel" json:"split_tunnel"`
	SplitTunnelRules string `yaml:"split_tunnel_rules" json:"split_tunnel_rules"`
	SplitTunnelMode  string `yaml:"split_tunnel_mode" json:"split_tunnel_mode"`

	MTU int `yaml:"mtu" json:"mtu"`
	//ChaffSec      int    `yaml:"chaff" json:"chaff"`
	ObfsPreset string `yaml:"obfs_preset" json:"obfs_preset"`
	UDPOnly    bool   `yaml:"udp_only" json:"udp_only"`
	// ChaffDist     string  `yaml:"chaff_dist" json:"chaff_dist"`
	// ChaffAlpha    float64 `yaml:"chaff_alpha" json:"chaff_alpha"`
	// ChaffXm       float64 `yaml:"chaff_xm" json:"chaff_xm"`
	// ChaffSizeMin  int     `yaml:"chaff_size_min" json:"chaff_size_min"`
	// ChaffSizeMax  int     `yaml:"chaff_size_max" json:"chaff_size_max"`
	// ShapeMeanMs   int     `yaml:"shape_mean_ms" json:"shape_mean_ms"`
	// ShapeTarget   int     `yaml:"shape_target" json:"shape_target"`

	UseTLS bool `yaml:"use_tls" json:"use_tls"`

	Routing *ClientRoutingConfig `yaml:"routing,omitempty" json:"routing,omitempty"`

	KillSwitch *ClientKillSwitchConfig `yaml:"kill_switch,omitempty" json:"kill_switch,omitempty"`

	ASNBypass *ClientASNBypassConfig `yaml:"asn_bypass,omitempty" json:"asn_bypass,omitempty"`

	Transport string `yaml:"transport,omitempty" json:"transport,omitempty"`

	TransportWhitelist []string `yaml:"transport_whitelist,omitempty" json:"transport_whitelist,omitempty"`
	TransportBlacklist []string `yaml:"transport_blacklist,omitempty" json:"transport_blacklist,omitempty"`

	RussianService string `yaml:"russian_service,omitempty" json:"russian_service,omitempty"`

	TransportConfig map[string]interface{} `yaml:"transport_config,omitempty" json:"transport_config,omitempty"`

	SubscriptionURL string `yaml:"subscription_url,omitempty" json:"subscription_url,omitempty"`

	ForceSNI string `yaml:"force_sni,omitempty" json:"force_sni,omitempty"`
}

type ClientRoutingConfig struct {
	Rules []ClientRoutingRule `yaml:"rules" json:"rules"`
}

type ClientRoutingRule struct {
	Type     string   `yaml:"type" json:"type"`
	Domain   []string `yaml:"domain,omitempty" json:"domain,omitempty"`
	IP       []string `yaml:"ip,omitempty" json:"ip,omitempty"`
	Port     string   `yaml:"port,omitempty" json:"port,omitempty"`
	Network  string   `yaml:"network,omitempty" json:"network,omitempty"`
	Enabled  bool     `yaml:"enabled" json:"enabled"`
	Priority int      `yaml:"priority" json:"priority"`
}

type ClientDNSConfig struct {
	Upstream    string `yaml:"upstream" json:"upstream"`
	FakeIPRange string `yaml:"fake_ip_range" json:"fake_ip_range"`
}

type ClientAdBlockConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// MLEnabled     bool          `yaml:"ml_enabled" json:"ml_enabled"`
}

type AdBlockRule struct {
	Domain string `yaml:"domain,omitempty" json:"domain,omitempty"`
	URL    string `yaml:"url,omitempty" json:"url,omitempty"`
	Type   string `yaml:"type" json:"type"`
}

type ClientKillSwitchConfig struct {
	Enabled      bool     `yaml:"enabled" json:"enabled"`
	AllowLAN     bool     `yaml:"allow_lan" json:"allow_lan"`
	AllowDNS     bool     `yaml:"allow_dns" json:"allow_dns"`
	PersistRules bool     `yaml:"persist_rules" json:"persist_rules"`
	AllowedIPs   []string `yaml:"allowed_ips,omitempty" json:"allowed_ips,omitempty"`
}

type ClientFailoverConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	Timeout int  `yaml:"timeout" json:"timeout"`
}

type ClientASNBypassConfig struct {
	Enabled         bool   `yaml:"enabled" json:"enabled"`
	TLSFingerprint  string `yaml:"tls_fingerprint" json:"tls_fingerprint"`
	DomainFrontHost string `yaml:"front_host" json:"front_host"`
}

func LoadClient(path string) (*ClientConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg ClientConfig
	switch ext := filepath.Ext(path); ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(b, &cfg); err != nil {
			return nil, err
		}
	case ".json":
		if err := json.Unmarshal(b, &cfg); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unsupported config format")
	}
	return &cfg, nil
}
