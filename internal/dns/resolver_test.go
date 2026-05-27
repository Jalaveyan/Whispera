package dns

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestPositiveCacheServedWithoutQuery(t *testing.T) {
	r := NewResolver(DefaultConfig())
	want := net.IPv4(203, 0, 113, 7)
	r.putToCache("host.example", []net.IP{want})

	ips, err := r.Resolve(context.Background(), "host.example")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(want) {
		t.Fatalf("got %v want %v", ips, want)
	}
}

func TestNegativeCache(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NegativeTTL = 50 * time.Millisecond
	r := NewResolver(cfg)

	r.putNegative("bad.example")

	if _, ok := r.cacheLookup("bad.example"); !ok {
		t.Fatal("negative entry should be cached")
	}
	if ips, err := r.Resolve(context.Background(), "bad.example"); err != errNXCached || len(ips) != 0 {
		t.Fatalf("expected negative-cached error, got ips=%v err=%v", ips, err)
	}

	time.Sleep(70 * time.Millisecond)
	if _, ok := r.cacheLookup("bad.example"); ok {
		t.Fatal("negative entry should have expired")
	}
}

func TestResolveIPLiteral(t *testing.T) {
	r := NewResolver(DefaultConfig())
	ips, err := r.Resolve(context.Background(), "198.51.100.9")
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.IPv4(198, 51, 100, 9)) {
		t.Fatalf("got ips=%v err=%v", ips, err)
	}
}
