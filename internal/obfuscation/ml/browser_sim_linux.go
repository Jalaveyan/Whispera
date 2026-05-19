//go:build linux

package ml

import (
	"context"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"time"
)

// decoyTargets are Russian services that TSPU will never block.
// The server makes real HTTPS requests to them so tcpdump captures genuine
// browser-like traffic on port 443, which is labeled FlowDecoy for GAN training.
var decoyTargets = []struct {
	host  string
	paths []string
}{
	{"rutube.ru", []string{"/", "/video/person/2474646/", "/trending/"}},
	{"music.yandex.ru", []string{"/", "/users/ya.playlist/playlists/3/"}},
	{"vk.com", []string{"/video", "/feed"}},
	{"ok.ru", []string{"/video", "/"}},
	{"www.ivi.ru", []string{"/", "/movies/"}},
}

var simUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
}

// RunBrowserSim makes periodic HTTPS requests to Russian CDNs from the server,
// registers the outbound connections as FlowDecoy, and lets the pcap collector
// capture them as genuine positive examples for the GAN discriminator.
func RunBrowserSim(ctx context.Context) {
	transport := &http.Transport{
		DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(dialCtx, network, addr)
			if err != nil {
				return nil, err
			}
			// Register before TLS handshake so the flow accumulator gets the label
			// on the first packet it sees.
			FlowRegistry.RegisterConn(conn.LocalAddr(), conn.RemoteAddr(), FlowDecoy)
			return &simConn{Conn: conn}, nil
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       60 * time.Second,
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}

	for {
		// Random interval 20–60s to avoid a fixed fingerprint.
		delay := time.Duration(20000+mrand.Intn(40000)) * time.Millisecond
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}

		t := decoyTargets[mrand.Intn(len(decoyTargets))]
		path := t.paths[mrand.Intn(len(t.paths))]
		ua := simUserAgents[mrand.Intn(len(simUserAgents))]

		req, err := http.NewRequestWithContext(ctx, "GET", "https://"+t.host+path, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
		req.Header.Set("Accept-Language", "ru-RU,ru;q=0.9,en;q=0.8")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		req.Header.Set("Cache-Control", "no-cache")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		// Read up to 256 KB to produce realistic packet-size distribution.
		io.Copy(io.Discard, io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
	}
}

// simConn deregisters the flow from FlowRegistry when the TCP connection closes.
type simConn struct{ net.Conn }

func (c *simConn) Close() error {
	FlowRegistry.DeleteConn(c.Conn.LocalAddr(), c.Conn.RemoteAddr())
	return c.Conn.Close()
}
