package outbound

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"whispera/internal/logger"
)

var log = logger.Module("outbound")

type ChainConfig struct {
	Chain []string `yaml:"chain" json:"chain"`
	RetryCount int `yaml:"retry_count" json:"retry_count"`
	HopTimeout time.Duration `yaml:"hop_timeout" json:"hop_timeout"`
}

type Outbound struct {
	Tag      string
	Protocol string
	Address  string
	Settings map[string]interface{}
}

type Chain struct {
	mu        sync.RWMutex
	outbounds map[string]*Outbound
	config    *ChainConfig
}

func NewChain(cfg *ChainConfig) *Chain {
	if cfg == nil {
		cfg = &ChainConfig{
			RetryCount: 3,
			HopTimeout: 10 * time.Second,
		}
	}
	return &Chain{
		outbounds: make(map[string]*Outbound),
		config:    cfg,
	}
}

func (c *Chain) AddOutbound(out *Outbound) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.outbounds[out.Tag] = out
	log.Printf("Registered outbound: %s (%s -> %s)", out.Tag, out.Protocol, out.Address)
}

func (c *Chain) SetChain(tags []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config.Chain = tags
	log.Printf("Outbound chain set: %v", tags)
}

func (c *Chain) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	c.mu.RLock()
	chain := c.config.Chain
	c.mu.RUnlock()

	if len(chain) == 0 {
		return (&net.Dialer{Timeout: c.config.HopTimeout}).DialContext(ctx, network, address)
	}
	var conn net.Conn
	var err error

	for i, tag := range chain {
		out, exists := c.outbounds[tag]
		if !exists {
			return nil, fmt.Errorf("outbound not found: %s", tag)
		}

		if i == 0 {
			conn, err = c.dialOutbound(ctx, out, address)
		} else {
			conn, err = c.dialThroughProxy(ctx, conn, out, address)
		}

		if err != nil {
			if conn != nil {
				conn.Close()
			}
			return nil, fmt.Errorf("chain hop %d (%s) failed: %w", i+1, tag, err)
		}

		log.Printf("Chain hop %d: %s -> %s", i+1, tag, out.Address)
	}

	return conn, nil
}

func (c *Chain) dialOutbound(ctx context.Context, out *Outbound, target string) (net.Conn, error) {
	switch out.Protocol {
	case "direct":
		return (&net.Dialer{Timeout: c.config.HopTimeout}).DialContext(ctx, "tcp", target)
	case "socks5":
		return c.dialSOCKS5(out.Address, target)
	case "http":
		return c.dialHTTPProxy(out.Address, target)
	default:
		return (&net.Dialer{Timeout: c.config.HopTimeout}).DialContext(ctx, "tcp", out.Address)
	}
}

func (c *Chain) dialThroughProxy(ctx context.Context, conn net.Conn, out *Outbound, target string) (net.Conn, error) {
	switch out.Protocol {
	case "socks5":
		return c.dialSOCKS5Through(conn, target)
	case "http":
		return c.dialHTTPThrough(conn, target)
	default:
		return conn, nil
	}
}

func (c *Chain) dialSOCKS5(proxyAddr, target string) (net.Conn, error) {
	conn, err := (&net.Dialer{Timeout: c.config.HopTimeout}).DialContext(context.Background(), "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	return c.dialSOCKS5Through(conn, target)
}
func (c *Chain) dialSOCKS5Through(conn net.Conn, target string) (net.Conn, error) {
	host, portStr, _ := net.SplitHostPort(target)

	conn.Write([]byte{0x05, 0x01, 0x00})

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}

	req := []byte{0x05, 0x01, 0x00, 0x03}
	req = append(req, byte(len(host)))
	req = append(req, []byte(host)...)

	var port int
	fmt.Sscanf(portStr, "%d", &port)
	req = append(req, byte(port>>8), byte(port&0xff))

	conn.Write(req)

	resp = make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}

	if resp[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 connect failed: %d", resp[1])
	}

	return conn, nil
}

func (c *Chain) dialHTTPProxy(proxyAddr, target string) (net.Conn, error) {
	conn, err := (&net.Dialer{Timeout: c.config.HopTimeout}).DialContext(context.Background(), "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	return c.dialHTTPThrough(conn, target)
}

func (c *Chain) dialHTTPThrough(conn net.Conn, target string) (net.Conn, error) {
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	conn.Write([]byte(req))

	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err != nil {
		return nil, err
	}

	if n < 12 || string(resp[9:12]) != "200" {
		return nil, fmt.Errorf("HTTP CONNECT failed: %s", string(resp[:n]))
	}

	return conn, nil
}

func (c *Chain) GetOutbounds() []*Outbound {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]*Outbound, 0, len(c.outbounds))
	for _, out := range c.outbounds {
		result = append(result, out)
	}
	return result
}

func (c *Chain) GetChain() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.config.Chain
}
