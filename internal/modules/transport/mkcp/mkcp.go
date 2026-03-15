package mkcp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/reedsolomon"

	"whispera/internal/core/base"
	"whispera/internal/logger"
)

var log = logger.Module("mkcp")

const (
	ModuleName    = "transport.mkcp"
	ModuleVersion = "1.0.0"

	packetTypeData  = 0x01
	packetTypeAck   = 0x02
	packetTypeFEC   = 0x05
	packetTypeClose = 0x06

	defaultDataShards   = 10
	defaultParityShards = 3

	defaultRTT      = 100 * time.Millisecond
	defaultInterval = 30 * time.Millisecond
	defaultTimeout  = 30 * time.Second
	maxPacketSize   = 1400
	headerSize      = 24

	defaultCongestionWindow = 32
	maxCongestionWindow     = 1024
)

type Config struct {
	ListenAddr string
	RemoteAddr string

	DataShards   int
	ParityShards int
	EnableFEC    bool

	CongestionWindow int
	NoDelay          bool
	Interval         time.Duration
	Resend           int
	NoCongestion     bool

	EnableCrypt bool
	CryptKey    []byte

	RTT       time.Duration
	Timeout   time.Duration
	KeepAlive time.Duration

	SendBuffer    int
	ReceiveBuffer int

	Mode string
}

func DefaultConfig() *Config {
	return &Config{
		DataShards:       defaultDataShards,
		ParityShards:     defaultParityShards,
		EnableFEC:        true,
		CongestionWindow: defaultCongestionWindow,
		NoDelay:          true,
		Interval:         defaultInterval,
		Resend:           2,
		NoCongestion:     false,
		RTT:              defaultRTT,
		Timeout:          defaultTimeout,
		KeepAlive:        10 * time.Second,
		SendBuffer:       4 * 1024 * 1024,
		ReceiveBuffer:    4 * 1024 * 1024,
		Mode:             "fast",
	}
}

func (c *Config) ApplyMode(mode string) {
	switch mode {
	case "normal":
		c.NoDelay = false
		c.Interval = 40 * time.Millisecond
		c.Resend = 2
		c.NoCongestion = false
	case "fast":
		c.NoDelay = false
		c.Interval = 30 * time.Millisecond
		c.Resend = 2
		c.NoCongestion = true
	case "fast2":
		c.NoDelay = true
		c.Interval = 20 * time.Millisecond
		c.Resend = 2
		c.NoCongestion = true
	case "fast3":
		c.NoDelay = true
		c.Interval = 10 * time.Millisecond
		c.Resend = 1
		c.NoCongestion = true
	default:
	}
}

func (c *Config) Validate() error {
	if c.DataShards <= 0 {
		c.DataShards = defaultDataShards
	}
	if c.ParityShards < 0 {
		c.ParityShards = defaultParityShards
	}
	if c.CongestionWindow <= 0 {
		c.CongestionWindow = defaultCongestionWindow
	}
	if c.Mode != "" {
		c.ApplyMode(c.Mode)
	}
	return nil
}

type Segment struct {
	conv     uint32
	cmd      uint8
	frg      uint8
	wnd      uint16
	ts       uint32
	sn       uint32
	una      uint32
	data     []byte
	resendTs time.Time
	rto      time.Duration
	fastack  uint32
	xmit     uint32
}

type Connection struct {
	mu    sync.RWMutex
	conv  uint32
	state int32

	conn   net.PacketConn
	remote net.Addr

	sendBuf []*Segment
	recvBuf []*Segment
	sendWnd []uint32
	recvWnd []uint32

	sndUna uint32
	sndNxt uint32
	rcvNxt uint32

	sndWnd   uint32
	rcvWnd   uint32
	rmt_wnd  uint32
	cwnd     uint32
	ssthresh uint32

	rx_rtt    time.Duration
	rx_srtt   time.Duration
	rx_rttval time.Duration
	rx_rto    time.Duration
	rx_minrto time.Duration

	fec        *FECEncoder
	fecDecoder *FECDecoder

	recvQueue chan []byte

	config *Config

	fecDataShards   int
	fecParityShards int

	bytesIn      uint64
	bytesOut     uint64
	packetsIn    uint64
	packetsOut   uint64
	retransmits  uint64
	fecRecovered uint64

	lastRecv time.Time
	lastSend time.Time

	closeOnce sync.Once
	closeCh   chan struct{}
}

type FECEncoder struct {
	enc          reedsolomon.Encoder
	dataShards   int
	parityShards int
	shardSize    int
	shards       [][]byte
	current      int
}

func NewFECEncoder(dataShards, parityShards, shardSize int) *FECEncoder {
	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		log.Error("Failed to create RS encoder: %v", err)
		return nil
	}

	shards := make([][]byte, dataShards+parityShards)
	for i := range shards {
		shards[i] = make([]byte, shardSize)
	}

	return &FECEncoder{
		enc:          enc,
		dataShards:   dataShards,
		parityShards: parityShards,
		shardSize:    shardSize,
		shards:       shards,
	}
}

func (e *FECEncoder) Encode(data []byte) [][]byte {
	copy(e.shards[e.current], data)
	e.current++

	if e.current >= e.dataShards {
		for i := e.current; i < e.dataShards; i++ {
			for j := range e.shards[i] {
				e.shards[i][j] = 0
			}
		}

		err := e.enc.Encode(e.shards)
		if err != nil {
			log.Error("FEC encode failed: %v", err)
			e.current = 0
			return nil
		}

		e.current = 0
		return e.shards[e.dataShards:]
	}
	return nil
}

type FECDecoder struct {
	dataShards   int
	parityShards int
	shardSize    int
	groups map[uint32][][]byte
	counts map[uint32]int
	mu     sync.Mutex
}

func NewFECDecoder(dataShards, parityShards, shardSize int) *FECDecoder {
	return &FECDecoder{
		dataShards:   dataShards,
		parityShards: parityShards,
		shardSize:    shardSize,
		groups:       make(map[uint32][][]byte),
		counts:       make(map[uint32]int),
	}
}

func (d *FECDecoder) Decode(sn uint32, data []byte, isFEC bool, idx int, ds, ps int) [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()

	baseSN := sn - (sn % uint32(ds))
	if isFEC {
		baseSN = sn - (sn % uint32(ds))
	}

	totalShards := ds + ps
	group, exists := d.groups[baseSN]
	if !exists {
		group = make([][]byte, totalShards)
		d.groups[baseSN] = group
		d.counts[baseSN] = 0
	}

	shardIdx := 0
	if isFEC {
		shardIdx = ds + idx
	} else {
		shardIdx = int(sn % uint32(ds))
	}

	if shardIdx >= len(group) {
		return nil
	}

	if group[shardIdx] == nil {
		shard := make([]byte, len(data))
		copy(shard, data)
		group[shardIdx] = shard
		d.counts[baseSN]++
	}

	if d.counts[baseSN] >= ds {
		missing := false
		for i := 0; i < ds; i++ {
			if group[i] == nil {
				missing = true
				break
			}
		}

		if missing {
			enc, err := reedsolomon.New(ds, ps)
			if err != nil {
				return nil
			}

			if err := enc.Reconstruct(group); err == nil {
				var recovered [][]byte
				for i := 0; i < ds; i++ {
					if group[i] != nil {
						recovered = append(recovered, group[i])
					}
				}
				delete(d.groups, baseSN)
				delete(d.counts, baseSN)
				return recovered
			}
		} else {
			delete(d.groups, baseSN)
			delete(d.counts, baseSN)
		}
	} else {
	}

	return nil
}

type Transport struct {
	*base.Module
	config *Config

	mu       sync.RWMutex
	listener net.PacketConn
	conns    map[uint32]*Connection

	totalBytesIn  uint64
	totalBytesOut uint64
	activeConns   int32
}

func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	t := &Transport{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: cfg,
		conns:  make(map[uint32]*Connection),
	}

	return t, nil
}

func (t *Transport) Listen(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", t.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	t.mu.Lock()
	t.listener = conn
	t.mu.Unlock()

	log.Info("mKCP listening on %s", t.config.ListenAddr)

	go t.acceptLoop(ctx)

	return nil
}

func (t *Transport) acceptLoop(ctx context.Context) {
	buf := make([]byte, maxPacketSize)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, addr, err := t.listener.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Warn("Read error: %v", err)
			continue
		}

		if n < headerSize {
			continue
		}

		conv := binary.LittleEndian.Uint32(buf[:4])

		t.mu.RLock()
		conn, exists := t.conns[conv]
		t.mu.RUnlock()

		if !exists {
			conn = t.newConnection(conv, addr)
			t.mu.Lock()
			t.conns[conv] = conn
			t.mu.Unlock()
			atomic.AddInt32(&t.activeConns, 1)
		}

		conn.processPacket(buf[:n])
	}
}

func (t *Transport) newConnection(conv uint32, addr net.Addr) *Connection {
	conn := &Connection{
		conv:            conv,
		state:           1,
		conn:            t.listener,
		remote:          addr,
		sendBuf:         make([]*Segment, 0, 256),
		recvBuf:         make([]*Segment, 0, 256),
		sndWnd:          uint32(t.config.CongestionWindow),
		rcvWnd:          uint32(t.config.CongestionWindow),
		cwnd:            uint32(t.config.CongestionWindow),
		ssthresh:        uint32(maxCongestionWindow),
		rx_rto:          t.config.RTT,
		rx_minrto:       t.config.Interval,
		config:          t.config,
		recvQueue:       make(chan []byte, 256),
		closeCh:         make(chan struct{}),
		lastRecv:        time.Now(),
		lastSend:        time.Now(),
		fecDataShards:   t.config.DataShards,
		fecParityShards: t.config.ParityShards,
	}

	if t.config.EnableFEC {
		conn.fec = NewFECEncoder(t.config.DataShards, t.config.ParityShards, maxPacketSize)
		conn.fecDecoder = NewFECDecoder(t.config.DataShards, t.config.ParityShards, maxPacketSize)
	}

	go conn.flushLoop()

	return conn
}

func (t *Transport) Dial(ctx context.Context, address string) (net.Conn, error) {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}

	var convBuf [4]byte
	rand.Read(convBuf[:])
	conv := binary.LittleEndian.Uint32(convBuf[:])

	mkcpConn := &Connection{
		conv:      conv,
		state:     1,
		conn:      conn,
		remote:    addr,
		sendBuf:   make([]*Segment, 0, 256),
		recvBuf:   make([]*Segment, 0, 256),
		sndWnd:    uint32(t.config.CongestionWindow),
		rcvWnd:    uint32(t.config.CongestionWindow),
		cwnd:      uint32(t.config.CongestionWindow),
		ssthresh:  uint32(maxCongestionWindow),
		rx_rto:    t.config.RTT,
		rx_minrto: t.config.Interval,
		config:    t.config,
		recvQueue: make(chan []byte, 256),
		closeCh:   make(chan struct{}),
		lastRecv:  time.Now(),
		lastSend:  time.Now(),
	}

	if t.config.EnableFEC {
		mkcpConn.fec = NewFECEncoder(t.config.DataShards, t.config.ParityShards, maxPacketSize)
		mkcpConn.fecDecoder = NewFECDecoder(t.config.DataShards, t.config.ParityShards, maxPacketSize)
	}

	t.mu.Lock()
	t.conns[conv] = mkcpConn
	t.mu.Unlock()
	atomic.AddInt32(&t.activeConns, 1)

	go mkcpConn.readLoop()
	go mkcpConn.flushLoop()

	return mkcpConn, nil
}


func (c *Connection) Read(b []byte) (n int, err error) {
	select {
	case data := <-c.recvQueue:
		n = copy(b, data)
		atomic.AddUint64(&c.bytesIn, uint64(n))
		return n, nil
	case <-c.closeCh:
		return 0, io.EOF
	}
}

func (c *Connection) Write(b []byte) (n int, err error) {
	if atomic.LoadInt32(&c.state) != 1 {
		return 0, io.ErrClosedPipe
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for len(b) > 0 {
		size := len(b)
		if size > maxPacketSize-headerSize {
			size = maxPacketSize - headerSize
		}

		seg := &Segment{
			conv: c.conv,
			cmd:  packetTypeData,
			sn:   c.sndNxt,
			ts:   uint32(time.Now().UnixMilli()),
			data: make([]byte, size),
		}
		copy(seg.data, b[:size])

		c.sendBuf = append(c.sendBuf, seg)
		c.sndNxt++
		b = b[size:]
		n += size
	}

	atomic.AddUint64(&c.bytesOut, uint64(n))
	c.lastSend = time.Now()

	return n, nil
}

func (c *Connection) Close() error {
	c.closeOnce.Do(func() {
		atomic.StoreInt32(&c.state, 2)

		c.mu.Lock()
		seg := &Segment{
			conv: c.conv,
			cmd:  packetTypeClose,
			sn:   c.sndNxt,
		}
		c.sendBuf = append(c.sendBuf, seg)
		c.mu.Unlock()

		c.flush()

		close(c.closeCh)
		atomic.StoreInt32(&c.state, 0)
	})
	return nil
}

func (c *Connection) LocalAddr() net.Addr {
	if pc, ok := c.conn.(interface{ LocalAddr() net.Addr }); ok {
		return pc.LocalAddr()
	}
	return nil
}

func (c *Connection) RemoteAddr() net.Addr {
	return c.remote
}

func (c *Connection) SetDeadline(t time.Time) error {
	return nil
}

func (c *Connection) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *Connection) SetWriteDeadline(t time.Time) error {
	return nil
}

func (c *Connection) processPacket(data []byte) {
	if len(data) < headerSize {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.processPacketLocked(data, false)
}

func (c *Connection) processPacketLocked(data []byte, isRecovered bool) {
	cmd := data[4]
	sn := binary.LittleEndian.Uint32(data[8:12])
	ts := binary.LittleEndian.Uint32(data[12:16])
	una := binary.LittleEndian.Uint32(data[16:20])

	c.parseUna(una)

	switch cmd {
	case packetTypeData:
		c.processData(sn, data[headerSize:])
		c.sendAck(sn, ts)

	case packetTypeAck:
		c.processAck(sn, ts)

	case packetTypeFEC:
		if c.fecDecoder != nil {
			idx := int(data[5])
			params := binary.LittleEndian.Uint16(data[6:8])
			ds := int(params >> 8)
			ps := int(params & 0xFF)

			if ds > 0 && ps > 0 {
				recovered := c.fecDecoder.Decode(sn, data[headerSize:], true, idx, ds, ps)
				for _, pkt := range recovered {
					if len(pkt) >= headerSize {
						c.processPacketLocked(pkt, true)
						atomic.AddUint64(&c.fecRecovered, 1)
					}
				}
			}
		}

	case packetTypeClose:
		c.Close()
	default:
	}

	if !isRecovered {
		c.lastRecv = time.Now()
		atomic.AddUint64(&c.packetsIn, 1)
	}
}

func (c *Connection) processData(sn uint32, data []byte) {
	if sn < c.rcvNxt {
		return
	}
	if sn >= c.rcvNxt+c.rcvWnd {
		return
	}

	seg := &Segment{
		sn:   sn,
		data: make([]byte, len(data)),
	}
	copy(seg.data, data)
	c.recvBuf = append(c.recvBuf, seg)

	c.deliverData()
}

func (c *Connection) deliverData() {
	for len(c.recvBuf) > 0 {
		found := false
		for i, seg := range c.recvBuf {
			if seg.sn == c.rcvNxt {
				select {
				case c.recvQueue <- seg.data:
					c.rcvNxt++
					c.recvBuf = append(c.recvBuf[:i], c.recvBuf[i+1:]...)
					found = true
				default:
					return
				}
				break
			}
		}
		if !found {
			break
		}
	}
}

func (c *Connection) processAck(sn uint32, ts uint32) {
	rtt := time.Duration(uint32(time.Now().UnixMilli())-ts) * time.Millisecond
	c.updateRTT(rtt)

	for i, seg := range c.sendBuf {
		if seg.sn == sn {
			c.sendBuf = append(c.sendBuf[:i], c.sendBuf[i+1:]...)
			break
		}
	}
}

func (c *Connection) parseUna(una uint32) {
	for len(c.sendBuf) > 0 {
		if c.sendBuf[0].sn < una {
			c.sendBuf = c.sendBuf[1:]
		} else {
			break
		}
	}
	if una > c.sndUna {
		c.sndUna = una
	}
}

func (c *Connection) sendAck(sn uint32, ts uint32) {
	seg := &Segment{
		conv: c.conv,
		cmd:  packetTypeAck,
		sn:   sn,
		ts:   ts,
		una:  c.rcvNxt,
	}
	c.output(seg)
}

func (c *Connection) updateRTT(rtt time.Duration) {
	if c.rx_srtt == 0 {
		c.rx_srtt = rtt
		c.rx_rttval = rtt / 2
	} else {
		delta := rtt - c.rx_srtt
		if delta < 0 {
			delta = -delta
		}
		c.rx_rttval = (3*c.rx_rttval + delta) / 4
		c.rx_srtt = (7*c.rx_srtt + rtt) / 8
	}
	c.rx_rto = c.rx_srtt + 4*c.rx_rttval
	if c.rx_rto < c.rx_minrto {
		c.rx_rto = c.rx_minrto
	}
}

func (c *Connection) flushLoop() {
	ticker := time.NewTicker(c.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.flush()
		case <-c.closeCh:
			return
		}
	}
}

func (c *Connection) flush() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	for _, seg := range c.sendBuf {
		if seg.xmit == 0 {
			seg.xmit = 1
			seg.resendTs = now.Add(c.rx_rto)
			c.output(seg)
		} else if now.After(seg.resendTs) {
			seg.xmit++
			seg.resendTs = now.Add(c.rx_rto * time.Duration(seg.xmit))
			c.output(seg)
			atomic.AddUint64(&c.retransmits, 1)
		}
	}
}

func (c *Connection) output(seg *Segment) {
	buf := make([]byte, headerSize+len(seg.data))

	binary.LittleEndian.PutUint32(buf[0:4], seg.conv)
	buf[4] = seg.cmd
	buf[5] = seg.frg
	binary.LittleEndian.PutUint16(buf[6:8], seg.wnd)
	binary.LittleEndian.PutUint32(buf[8:12], seg.sn)
	binary.LittleEndian.PutUint32(buf[12:16], seg.ts)
	binary.LittleEndian.PutUint32(buf[16:20], seg.una)
	binary.LittleEndian.PutUint32(buf[20:24], uint32(len(seg.data)))

	copy(buf[headerSize:], seg.data)

	if c.fec != nil && seg.cmd == packetTypeData {
		fecPackets := c.fec.Encode(buf)
		for _, fecPkt := range fecPackets {
			fecBuf := make([]byte, headerSize+len(fecPkt))
			binary.LittleEndian.PutUint32(fecBuf[0:4], c.conv)
			fecBuf[4] = packetTypeFEC
			fecBuf[5] = 0

			ds := uint16(c.fecDataShards)
			ps := uint16(c.fecParityShards)
			binary.LittleEndian.PutUint16(fecBuf[6:8], (ds<<8)|ps)

			binary.LittleEndian.PutUint32(fecBuf[8:12], seg.sn)
			binary.LittleEndian.PutUint32(fecBuf[12:16], seg.ts)

			copy(fecBuf[headerSize:], fecPkt)
			c.conn.WriteTo(fecBuf, c.remote)
		}
	}

	c.conn.WriteTo(buf, c.remote)
	atomic.AddUint64(&c.packetsOut, 1)
}

func (c *Connection) readLoop() {
	buf := make([]byte, maxPacketSize)
	for atomic.LoadInt32(&c.state) == 1 {
		n, _, err := c.conn.ReadFrom(buf)
		if err != nil {
			if atomic.LoadInt32(&c.state) != 1 {
				return
			}
			continue
		}
		c.processPacket(buf[:n])
	}
}

func (c *Connection) Stats() map[string]interface{} {
	return map[string]interface{}{
		"bytes_in":      atomic.LoadUint64(&c.bytesIn),
		"bytes_out":     atomic.LoadUint64(&c.bytesOut),
		"packets_in":    atomic.LoadUint64(&c.packetsIn),
		"packets_out":   atomic.LoadUint64(&c.packetsOut),
		"retransmits":   atomic.LoadUint64(&c.retransmits),
		"fec_recovered": atomic.LoadUint64(&c.fecRecovered),
		"rtt":           c.rx_srtt.String(),
		"rto":           c.rx_rto.String(),
		"cwnd":          c.cwnd,
	}
}


func (t *Transport) Init(ctx context.Context) error {
	return nil
}

func (t *Transport) Start(ctx context.Context) error {
	if t.config.ListenAddr != "" {
		return t.Listen(ctx)
	}
	return nil
}

func (t *Transport) Stop(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, conn := range t.conns {
		conn.Close()
	}

	if t.listener != nil {
		t.listener.Close()
	}

	return nil
}

func (t *Transport) Stats() map[string]interface{} {
	return map[string]interface{}{
		"total_bytes_in":  atomic.LoadUint64(&t.totalBytesIn),
		"total_bytes_out": atomic.LoadUint64(&t.totalBytesOut),
		"active_conns":    atomic.LoadInt32(&t.activeConns),
	}
}

