package split_tunnel

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	stdlog "log"
)

const (
	GeoIPSourceURL   = "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/ru.txt"
	GeoIPMirrorURL   = "https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/text/ru.txt"
	geoIPRefresh     = 24 * time.Hour
	geoIPRetryMin    = 15 * time.Second
	geoIPRetryMax    = 5 * time.Minute
	geoIPRetryEmpty  = 30 * time.Second
	geoIPMaxBytes    = 8 << 20
	geoIPMinNetworks = 100
)

type ipRange struct{ lo, hi [16]byte }

type GeoIPSet struct {
	mu     sync.RWMutex
	ranges []ipRange
	etag   string
}

func NewGeoIPSet() *GeoIPSet { return &GeoIPSet{} }

func (g *GeoIPSet) Len() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.ranges)
}

func (g *GeoIPSet) Contains(ip net.IP) bool {
	v16 := ip.To16()
	if v16 == nil {
		return false
	}
	var addr [16]byte
	copy(addr[:], v16)

	g.mu.RLock()
	defer g.mu.RUnlock()

	i := sort.Search(len(g.ranges), func(i int) bool {
		return bytes.Compare(g.ranges[i].hi[:], addr[:]) >= 0
	})
	return i < len(g.ranges) && bytes.Compare(g.ranges[i].lo[:], addr[:]) <= 0
}

func rangeOf(ipnet *net.IPNet) (ipRange, bool) {
	ip := ipnet.IP.To16()
	if ip == nil {
		return ipRange{}, false
	}
	ones, bits := ipnet.Mask.Size()
	if bits == 0 {
		return ipRange{}, false
	}
	if bits == 32 {
		ones += 96
	}
	var r ipRange
	copy(r.lo[:], ip)
	copy(r.hi[:], ip)
	for i := ones; i < 128; i++ {
		r.hi[i/8] |= 1 << (7 - uint(i%8))
	}
	return r, true
}

func parseGeoIP(r io.Reader) ([]ipRange, error) {
	var out []ipRange
	sc := bufio.NewScanner(io.LimitReader(r, geoIPMaxBytes))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, ipnet, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		r, ok := rangeOf(ipnet)
		if !ok {
			continue
		}
		out = append(out, r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		return bytes.Compare(out[i].hi[:], out[j].hi[:]) < 0
	})
	return out, nil
}

func (g *GeoIPSet) load(r io.Reader) (int, error) {
	ranges, err := parseGeoIP(r)
	if err != nil {
		return 0, err
	}
	if len(ranges) < geoIPMinNetworks {
		return 0, fmt.Errorf("geoip: got %d networks, refusing to replace a working list", len(ranges))
	}
	g.mu.Lock()
	g.ranges = ranges
	g.mu.Unlock()
	return len(ranges), nil
}

func (g *GeoIPSet) LoadFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return g.load(f)
}

func (g *GeoIPSet) Refresh(ctx context.Context, client *http.Client, url, cachePath string) (int, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, false, err
	}
	g.mu.RLock()
	etag := g.etag
	g.mu.RUnlock()
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return g.Len(), false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return 0, false, fmt.Errorf("geoip: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, geoIPMaxBytes))
	if err != nil {
		return 0, false, err
	}
	n, err := g.load(strings.NewReader(string(body)))
	if err != nil {
		return 0, false, err
	}

	g.mu.Lock()
	g.etag = resp.Header.Get("ETag")
	g.mu.Unlock()

	if cachePath != "" {
		if err := writeCache(cachePath, body); err != nil {
			stdlog.Printf("[geoip] cache write failed: %v", err)
		}
	}
	return n, true, nil
}

func writeCache(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (g *GeoIPSet) KeepFresh(ctx context.Context, client *http.Client, cachePath string) {
	if n, err := g.LoadFile(cachePath); err == nil {
		stdlog.Printf("[geoip] loaded %d networks from cache", n)
	}

	refresh := func() bool {
		for _, url := range []string{GeoIPSourceURL, GeoIPMirrorURL} {
			reqCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
			n, changed, err := g.Refresh(reqCtx, client, url, cachePath)
			cancel()
			if err != nil {
				continue
			}
			if changed {
				stdlog.Printf("[geoip] updated, %d networks", n)
			} else {
				stdlog.Printf("There are currently no changes to the geo files.")
			}
			return true
		}
		return false
	}

	retry := geoIPRetryMin
	for {
		var wait time.Duration
		if refresh() {
			wait, retry = geoIPRefresh, geoIPRetryMin
		} else {
			ceiling := geoIPRetryMax
			if g.Len() == 0 {
				ceiling = geoIPRetryEmpty
			}
			if retry > ceiling {
				retry = ceiling
			}
			stdlog.Printf("[geoip] refresh failed, keeping %d networks, retry in %s", g.Len(), retry)
			wait = retry
			if retry < ceiling {
				retry *= 2
			}
		}

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
