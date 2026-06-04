package metrics

import "sync/atomic"

type Counter struct {
	value int64
}

func (c *Counter) Value() int64 {
	return atomic.LoadInt64(&c.value)
}

type CounterVec struct {
	counters map[string]*Counter
}

func NewCounterVec() *CounterVec {
	return &CounterVec{
		counters: make(map[string]*Counter),
	}
}

var (
	PacketsRx            = &Counter{}
	PacketsTx            = &Counter{}
	BytesRx              = &Counter{}
	BytesTx              = &Counter{}
	PacketsRxByTransport = NewCounterVec()
	PacketsTxByTransport = NewCounterVec()
	BytesRxByTransport   = NewCounterVec()
	BytesTxByTransport   = NewCounterVec()

	XHTTPStreamsCreated   = &Counter{}
	XHTTPSessionsCreated  = &Counter{}
	XHTTPSessionsActive   = &Gauge{}
	XHTTPSessionDuration  = &Histogram{}
	XHTTPSessionsTimeout  = &Counter{}
	XHTTPBufferPoolHits   = &Counter{}
	XHTTPBufferPoolMisses = &Counter{}
)

type Gauge struct {
	value int64
}

func (g *Gauge) Value() int64 {
	return atomic.LoadInt64(&g.value)
}

type Histogram struct {
	count int64
	sum   int64
}
