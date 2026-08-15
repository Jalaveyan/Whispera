package split_tunnel

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleList(n int) string {
	var b strings.Builder
	b.WriteString("# comment line\n\n")
	b.WriteString("5.8.0.0/19\n")
	b.WriteString("87.240.128.0/18\n")
	b.WriteString("2a00:1450::/32\n")
	for i := range n {
		fmt.Fprintf(&b, "203.%d.%d.0/24\n", i/256, i%256)
	}
	return b.String()
}

func TestGeoIPContains(t *testing.T) {
	g := NewGeoIPSet()
	if _, err := g.load(strings.NewReader(sampleList(200))); err != nil {
		t.Fatal(err)
	}

	for _, ip := range []string{"5.8.0.1", "5.8.31.255", "87.240.132.67"} {
		if !g.Contains(net.ParseIP(ip)) {
			t.Fatalf("%s must be inside the list", ip)
		}
	}
	for _, ip := range []string{"5.7.255.255", "5.8.32.0", "8.8.8.8"} {
		if g.Contains(net.ParseIP(ip)) {
			t.Fatalf("%s must be outside the list", ip)
		}
	}
	if !g.Contains(net.ParseIP("2a00:1450::1")) {
		t.Fatal("IPv6 network from the list must match — half of a country list is IPv6")
	}
	if g.Contains(net.ParseIP("2a00:1451::1")) {
		t.Fatal("IPv6 outside the list must not match")
	}
}

func TestGeoIPRejectsTruncatedList(t *testing.T) {
	g := NewGeoIPSet()
	if _, err := g.load(strings.NewReader(sampleList(200))); err != nil {
		t.Fatal(err)
	}
	before := g.Len()

	if _, err := g.load(strings.NewReader("1.2.3.0/24\n")); err == nil {
		t.Fatal("a suspiciously short list must be rejected, not applied")
	}
	if g.Len() != before {
		t.Fatalf("working list must survive a bad update: %d -> %d", before, g.Len())
	}
}

func TestGeoIPRefreshUsesETag(t *testing.T) {
	var hits, conditional int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("If-None-Match") == `"v1"` {
			conditional++
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		fmt.Fprint(w, sampleList(200))
	}))
	defer srv.Close()

	cache := filepath.Join(t.TempDir(), "ru.txt")
	g := NewGeoIPSet()

	n, changed, err := g.Refresh(context.Background(), srv.Client(), srv.URL, cache)
	if err != nil || !changed || n != 203 {
		t.Fatalf("first refresh: n=%d changed=%v err=%v", n, changed, err)
	}
	if _, err := os.Stat(cache); err != nil {
		t.Fatalf("cache must be written: %v", err)
	}

	_, changed, err = g.Refresh(context.Background(), srv.Client(), srv.URL, cache)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("unchanged list must not be reapplied")
	}
	if conditional != 1 {
		t.Fatalf("second request must carry If-None-Match, got %d conditional of %d", conditional, hits)
	}
}

func TestGeoIPLoadFromCache(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "ru.txt")
	if err := os.WriteFile(cache, []byte(sampleList(200)), 0o644); err != nil {
		t.Fatal(err)
	}
	g := NewGeoIPSet()
	n, err := g.LoadFile(cache)
	if err != nil || n != 203 {
		t.Fatalf("LoadFile: n=%d err=%v", n, err)
	}
	if !g.Contains(net.ParseIP("87.240.132.67")) {
		t.Fatal("cached list must be usable before any network access")
	}
}

func TestSplitTunnelUsesGeoIP(t *testing.T) {
	g := NewGeoIPSet()
	if _, err := g.load(strings.NewReader(sampleList(200))); err != nil {
		t.Fatal(err)
	}

	stm := NewSplitTunnelManager()
	stm.SetEnabled(true)
	stm.SetGeoIP(g)

	if !stm.ShouldBypassByIP("87.240.132.67") {
		t.Fatal("address from the country list must bypass the tunnel")
	}
	if stm.ShouldBypassByIP("8.8.8.8") {
		t.Fatal("foreign address must stay in the tunnel")
	}

	stm.AddRule(&SplitTunnelRule{
		Type: "ip", Value: "87.240.128.0/18", Action: "tunnel", Enabled: true, Priority: 100,
	})
	if stm.ShouldBypassByIP("87.240.132.67") {
		t.Fatal("user rule must override the country list")
	}
}
