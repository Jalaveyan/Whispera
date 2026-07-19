package tunnel

import (
	"context"
	"math"
	"net"
	"time"

	"github.com/nekoskin/whispera/neural"
	"github.com/sourcegraph/conc/iter"
)

type mlOrchestrator struct {
	m *Manager

	tspuDetector tspuDetectorIface
}

func newMLOrchestrator(m *Manager) *mlOrchestrator {
	return &mlOrchestrator{
		m:            m,
		tspuDetector: neural.NewTSPUDetector(),
	}
}

func probeLatency(ctx context.Context, addr string, timeout time.Duration) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	conn.Close()
	return time.Since(start), nil
}

type serverProbe struct {
	Addr    string
	Latency time.Duration
}

func (ml *mlOrchestrator) pickServer(ctx context.Context) string {
	candidates := ml.regionCandidates()
	if len(candidates) == 0 {
		return ""
	}

	probes := iter.Map(candidates, func(a *string) serverProbe {
		addr := *a
		lat, err := probeLatency(ctx, addr, 200*time.Millisecond)
		if err != nil {
			return serverProbe{Addr: addr, Latency: math.MaxInt64}
		}
		return serverProbe{Addr: addr, Latency: lat}
	})

	best := probes[0]
	for _, p := range probes[1:] {
		if p.Latency < best.Latency {
			best = p
		}
	}
	if best.Latency == math.MaxInt64 {
		return ""
	}
	return best.Addr
}

func (ml *mlOrchestrator) regionCandidates() []string {
	m := ml.m
	region := m.config.PreferredRegion
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}

	if region != "" && region != "auto" {
		if servers, ok := m.config.Regions[region]; ok && len(servers) > 0 {
			for _, s := range servers {
				add(s)
			}
			return out
		}
	}

	for _, s := range m.config.ServerList {
		add(s)
	}
	for _, servers := range m.config.Regions {
		for _, s := range servers {
			add(s)
		}
	}
	return out
}
