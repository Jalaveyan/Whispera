package neural

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

var defaultRefSizeDist = [7]float64{0.04, 0.02, 0.02, 0.04, 0.08, 0.35, 0.45}

var defaultRefIATDist = [5]float64{0.55, 0.25, 0.10, 0.07, 0.03}

const minRefSamples = 500

const (
	klWindowSize    = 512
	klMinSamples    = 32
	klMaxReward     = 0.30
	klDecayPerReset = 200
)

type FlowObserver struct {
	mu sync.Mutex

	sizeCounts [7]int64
	iatCounts  [5]int64
	total      int64

	refSizeCounts [7]int64
	refIATCounts  [5]int64
	refTotal      int64

	lastPacketAt int64
}

func (f *FlowObserver) sizeBucket(n int) int {
	switch {
	case n <= 64:
		return 0
	case n <= 256:
		return 1
	case n <= 512:
		return 2
	case n <= 1024:
		return 3
	case n <= 1280:
		return 4
	case n <= 1400:
		return 5
	default:
		return 6
	}
}

func (f *FlowObserver) iatBucket(ms float64) int {
	switch {
	case ms < 1:
		return 0
	case ms < 5:
		return 1
	case ms < 20:
		return 2
	case ms < 100:
		return 3
	default:
		return 4
	}
}

func (f *FlowObserver) RecordPacket(sizeBytes int) {
	now := time.Now().UnixNano()
	prev := atomic.SwapInt64(&f.lastPacketAt, now)

	sb := f.sizeBucket(sizeBytes)
	ib := -1
	if prev > 0 {
		ib = f.iatBucket(float64(now-prev) / 1e6)
	}

	atomic.AddInt64(&f.sizeCounts[sb], 1)
	if ib >= 0 {
		atomic.AddInt64(&f.iatCounts[ib], 1)
	}
	total := atomic.AddInt64(&f.total, 1)

	if total%klDecayPerReset == 0 {
		f.mu.Lock()
		for i := range f.sizeCounts {
			atomic.StoreInt64(&f.sizeCounts[i], 0)
		}
		for i := range f.iatCounts {
			atomic.StoreInt64(&f.iatCounts[i], 0)
		}
		f.mu.Unlock()
	}
}

func (f *FlowObserver) UpdateReference(sizeBytes int, iatMs float64) {
	f.mu.Lock()
	f.refSizeCounts[f.sizeBucket(sizeBytes)]++
	if iatMs >= 0 {
		f.refIATCounts[f.iatBucket(iatMs)]++
	}
	f.refTotal++
	if f.refTotal > 0 && f.refTotal%4096 == 0 {
		for i := range f.refSizeCounts {
			f.refSizeCounts[i] /= 2
		}
		for i := range f.refIATCounts {
			f.refIATCounts[i] /= 2
		}
		f.refTotal /= 2
	}
	f.mu.Unlock()
}

func (f *FlowObserver) refDistributions() (sizeDist [7]float64, iatDist [5]float64) {
	if f.refTotal >= minRefSamples {
		for i, c := range f.refSizeCounts {
			sizeDist[i] = float64(c) / float64(f.refTotal)
		}
		var iatTot int64
		for _, c := range f.refIATCounts {
			iatTot += c
		}
		if iatTot > 0 {
			for i, c := range f.refIATCounts {
				iatDist[i] = float64(c) / float64(iatTot)
			}
		} else {
			iatDist = defaultRefIATDist
		}
		return sizeDist, iatDist
	}
	return defaultRefSizeDist, defaultRefIATDist
}

func (f *FlowObserver) KLReward() float64 {
	f.mu.Lock()
	total := atomic.LoadInt64(&f.total) % klDecayPerReset
	if total == 0 {
		total = klDecayPerReset
	}
	var sc [7]int64
	var ic [5]int64
	for i := range f.sizeCounts {
		sc[i] = atomic.LoadInt64(&f.sizeCounts[i])
	}
	for i := range f.iatCounts {
		ic[i] = atomic.LoadInt64(&f.iatCounts[i])
	}
	sizeDist, iatDist := f.refDistributions()
	f.mu.Unlock()

	if total < klMinSamples {
		return 0
	}

	var obsSizeDist [7]float64
	var obsIATDist [5]float64
	for i, c := range sc {
		obsSizeDist[i] = float64(c) / float64(total)
	}
	var iatTotal float64
	for _, c := range ic {
		iatTotal += float64(c)
	}
	if iatTotal > 0 {
		for i, c := range ic {
			obsIATDist[i] = float64(c) / iatTotal
		}
	}

	klSize := klDiv(obsSizeDist[:], sizeDist[:])
	klIAT := klDiv(obsIATDist[:], iatDist[:])

	kl := 0.65*klSize + 0.35*klIAT

	return klMaxReward * math.Exp(-3.0*kl)
}

func klDiv(p, q []float64) float64 {
	const eps = 1e-9
	var kl float64
	for i := range p {
		pi := p[i] + eps
		qi := q[i] + eps
		kl += pi * math.Log(pi/qi)
	}
	if math.IsNaN(kl) || math.IsInf(kl, 0) {
		return 2.0
	}
	if kl > 2.0 {
		kl = 2.0
	}
	return kl
}

var GlobalFlowObserver = &FlowObserver{}
