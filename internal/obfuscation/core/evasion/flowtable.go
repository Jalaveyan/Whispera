package evasion

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type FlowTableConfig struct {
	Enabled               bool          `yaml:"enabled" json:"enabled"`
	RotationInterval      time.Duration `yaml:"rotation_interval" json:"rotation_interval"`
	MaxConnectionAge      time.Duration `yaml:"max_connection_age" json:"max_connection_age"`
	FlowMultiplexing      bool          `yaml:"flow_multiplexing" json:"flow_multiplexing"`
	MultiplexCount        int           `yaml:"multiplex_count" json:"multiplex_count"`
	StateMachineConfusion bool          `yaml:"state_confusion" json:"state_confusion"`
	DecorrelateDirections bool          `yaml:"decorrelate_directions" json:"decorrelate_directions"`
}

func DefaultFlowTableConfig() *FlowTableConfig {
	return &FlowTableConfig{
		RotationInterval: 60 * time.Second,
		MaxConnectionAge: 5 * time.Minute,
		MultiplexCount:   3,
	}
}

type RotatingConn struct {
	mu        sync.Mutex
	inner     net.Conn
	dialer    func(ctx context.Context) (net.Conn, error)
	config    *FlowTableConfig
	stopCh    chan struct{}
	closed    int32
	created   time.Time
	rotations int64
}

func NewRotatingConn(conn net.Conn, dialer func(ctx context.Context) (net.Conn, error), cfg *FlowTableConfig) *RotatingConn {
	if cfg == nil {
		cfg = DefaultFlowTableConfig()
	}
	rc := &RotatingConn{
		inner:   conn,
		dialer:  dialer,
		config:  cfg,
		stopCh:  make(chan struct{}),
		created: time.Now(),
	}
	if cfg.RotationInterval > 0 {
		go rc.rotationLoop()
	}
	return rc
}

func (rc *RotatingConn) rotationLoop() {
	jitter := jitteredDuration(rc.config.RotationInterval, 20)
	ticker := time.NewTicker(jitter)
	defer ticker.Stop()

	for {
		select {
		case <-rc.stopCh:
			return
		case <-ticker.C:
			rc.rotate()
			jitter = jitteredDuration(rc.config.RotationInterval, 20)
			ticker.Reset(jitter)
		}
	}
}

func (rc *RotatingConn) rotate() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	newConn, err := rc.dialer(ctx)
	if err != nil {
		return
	}

	rc.mu.Lock()
	old := rc.inner
	rc.inner = newConn
	rc.created = time.Now()
	atomic.AddInt64(&rc.rotations, 1)
	rc.mu.Unlock()

	if old != nil {
		old.Close()
	}
}

func (rc *RotatingConn) Read(p []byte) (int, error) {
	rc.mu.Lock()
	conn := rc.inner
	rc.mu.Unlock()
	return conn.Read(p)
}

func (rc *RotatingConn) Write(p []byte) (int, error) {
	rc.mu.Lock()
	conn := rc.inner
	rc.mu.Unlock()
	return conn.Write(p)
}

func (rc *RotatingConn) Close() error {
	if !atomic.CompareAndSwapInt32(&rc.closed, 0, 1) {
		return nil
	}
	close(rc.stopCh)
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.inner != nil {
		return rc.inner.Close()
	}
	return nil
}

func (rc *RotatingConn) LocalAddr() net.Addr {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.inner.LocalAddr()
}

func (rc *RotatingConn) RemoteAddr() net.Addr {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.inner.RemoteAddr()
}

func (rc *RotatingConn) SetDeadline(t time.Time) error {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.inner.SetDeadline(t)
}

func (rc *RotatingConn) SetReadDeadline(t time.Time) error {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.inner.SetReadDeadline(t)
}

func (rc *RotatingConn) SetWriteDeadline(t time.Time) error {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.inner.SetWriteDeadline(t)
}

type MultiplexConn struct {
	conns    []net.Conn
	mu       sync.Mutex
	writeIdx uint64
	readIdx  uint64
	closed   int32
}

func NewMultiplexConn(conns []net.Conn) *MultiplexConn {
	return &MultiplexConn{conns: conns}
}

func (mc *MultiplexConn) Write(p []byte) (int, error) {
	idx := atomic.AddUint64(&mc.writeIdx, 1) % uint64(len(mc.conns))
	return mc.conns[idx].Write(p)
}

func (mc *MultiplexConn) Read(p []byte) (int, error) {
	idx := atomic.AddUint64(&mc.readIdx, 1) % uint64(len(mc.conns))
	return mc.conns[idx].Read(p)
}

func (mc *MultiplexConn) Close() error {
	if !atomic.CompareAndSwapInt32(&mc.closed, 0, 1) {
		return nil
	}
	var lastErr error
	for _, c := range mc.conns {
		if err := c.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func (mc *MultiplexConn) LocalAddr() net.Addr  { return mc.conns[0].LocalAddr() }
func (mc *MultiplexConn) RemoteAddr() net.Addr { return mc.conns[0].RemoteAddr() }
func (mc *MultiplexConn) SetDeadline(t time.Time) error {
	for _, c := range mc.conns {
		c.SetDeadline(t)
	}
	return nil
}
func (mc *MultiplexConn) SetReadDeadline(t time.Time) error {
	for _, c := range mc.conns {
		c.SetReadDeadline(t)
	}
	return nil
}
func (mc *MultiplexConn) SetWriteDeadline(t time.Time) error {
	for _, c := range mc.conns {
		c.SetWriteDeadline(t)
	}
	return nil
}

type BidirectionalConn struct {
	readConn  net.Conn
	writeConn net.Conn
	closed    int32
}

func NewBidirectionalConn(readConn, writeConn net.Conn) *BidirectionalConn {
	return &BidirectionalConn{readConn: readConn, writeConn: writeConn}
}

func (bc *BidirectionalConn) Read(p []byte) (int, error)  { return bc.readConn.Read(p) }
func (bc *BidirectionalConn) Write(p []byte) (int, error) { return bc.writeConn.Write(p) }
func (bc *BidirectionalConn) Close() error {
	if !atomic.CompareAndSwapInt32(&bc.closed, 0, 1) {
		return nil
	}
	bc.readConn.Close()
	return bc.writeConn.Close()
}
func (bc *BidirectionalConn) LocalAddr() net.Addr  { return bc.writeConn.LocalAddr() }
func (bc *BidirectionalConn) RemoteAddr() net.Addr { return bc.writeConn.RemoteAddr() }
func (bc *BidirectionalConn) SetDeadline(t time.Time) error {
	bc.readConn.SetDeadline(t)
	return bc.writeConn.SetDeadline(t)
}
func (bc *BidirectionalConn) SetReadDeadline(t time.Time) error {
	return bc.readConn.SetReadDeadline(t)
}
func (bc *BidirectionalConn) SetWriteDeadline(t time.Time) error {
	return bc.writeConn.SetWriteDeadline(t)
}

type StateMachineConfuser struct {
	conn   *net.TCPConn
	stopCh chan struct{}
}

func NewStateMachineConfuser(conn *net.TCPConn) *StateMachineConfuser {
	smc := &StateMachineConfuser{
		conn:   conn,
		stopCh: make(chan struct{}),
	}
	go smc.confusionLoop()
	return smc
}

func (smc *StateMachineConfuser) confusionLoop() {
	ticker := time.NewTicker(jitteredDuration(15*time.Second, 50))
	defer ticker.Stop()

	for {
		select {
		case <-smc.stopCh:
			return
		case <-ticker.C:
			smc.sendConfusion()
			ticker.Reset(jitteredDuration(15*time.Second, 50))
		}
	}
}

func (smc *StateMachineConfuser) sendConfusion() {
	setTTL(smc.conn, 1)
	fake := make([]byte, 8+randByte()%24)
	rand.Read(fake)
	smc.conn.Write(fake)
	setTTL(smc.conn, 64)
}

func DialWithFlowTableBypass(ctx context.Context, dialer func(ctx context.Context) (net.Conn, error), cfg *FlowTableConfig) (net.Conn, error) {
	if cfg == nil || !cfg.Enabled {
		return dialer(ctx)
	}

	if cfg.FlowMultiplexing && cfg.MultiplexCount > 1 {
		conns := make([]net.Conn, 0, cfg.MultiplexCount)
		for i := 0; i < cfg.MultiplexCount; i++ {
			c, err := dialer(ctx)
			if err != nil {
				for _, prev := range conns {
					prev.Close()
				}
				return dialer(ctx)
			}
			conns = append(conns, c)
		}
		return NewMultiplexConn(conns), nil
	}

	if cfg.DecorrelateDirections {
		c1, err := dialer(ctx)
		if err != nil {
			return nil, err
		}
		c2, err := dialer(ctx)
		if err != nil {
			c1.Close()
			return dialer(ctx)
		}
		return NewBidirectionalConn(c1, c2), nil
	}

	conn, err := dialer(ctx)
	if err != nil {
		return nil, err
	}

	if cfg.StateMachineConfusion {
		if tc, ok := conn.(*net.TCPConn); ok {
			NewStateMachineConfuser(tc)
		}
	}

	if cfg.RotationInterval > 0 {
		return NewRotatingConn(conn, dialer, cfg), nil
	}

	return conn, nil
}

func jitteredDuration(base time.Duration, jitterPercent int) time.Duration {
	var buf [8]byte
	rand.Read(buf[:])
	r := float64(binary.LittleEndian.Uint64(buf[:])) / float64(^uint64(0))
	jitter := float64(base) * float64(jitterPercent) / 100.0
	return time.Duration(float64(base) - jitter + r*2*jitter)
}

var _ net.Conn = (*RotatingConn)(nil)
var _ net.Conn = (*MultiplexConn)(nil)
var _ net.Conn = (*BidirectionalConn)(nil)
var _ net.Conn = (*DesyncConn)(nil)
var _ io.ReadWriteCloser = (*MultiplexConn)(nil)
