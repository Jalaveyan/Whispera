package quic

import (
	"context"
	"encoding/binary"
	"net"
	"runtime/debug"
	"strconv"
	"sync"
	"time"

	quicgo "github.com/quic-go/quic-go"
)

const (
	fecK                 = 10
	fecM                 = 4
	datagramMaxProtected = 1100
	fecSweepEvery        = 10 * time.Millisecond
	udpTargetIdle        = 2 * time.Minute
	targetDialTimeout    = 5 * time.Second
)

var fecBlockWait = 30 * time.Millisecond

const (
	markerFEC byte = 0xFF
	markerRaw byte = 0xFE
)

func encodeAddr(host string, port uint16) []byte {
	var b []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			b = append(b, 0x01)
			b = append(b, ip4...)
		} else {
			b = append(b, 0x04)
			b = append(b, ip.To16()...)
		}
	} else {
		b = append(b, 0x03, byte(len(host)))
		b = append(b, []byte(host)...)
	}
	return binary.BigEndian.AppendUint16(b, port)
}

func decodeAddr(b []byte) (host string, port uint16, rest []byte, ok bool) {
	if len(b) < 1 {
		return "", 0, nil, false
	}
	switch b[0] {
	case 0x01:
		if len(b) < 7 {
			return "", 0, nil, false
		}
		return net.IP(b[1:5]).String(), binary.BigEndian.Uint16(b[5:7]), b[7:], true
	case 0x04:
		if len(b) < 19 {
			return "", 0, nil, false
		}
		return net.IP(b[1:17]).String(), binary.BigEndian.Uint16(b[17:19]), b[19:], true
	case 0x03:
		if len(b) < 2 {
			return "", 0, nil, false
		}
		l := int(b[1])
		if len(b) < 2+l+2 {
			return "", 0, nil, false
		}
		return string(b[2 : 2+l]), binary.BigEndian.Uint16(b[2+l : 4+l]), b[4+l:], true
	default:
		return "", 0, nil, false
	}
}

type fecSender struct {
	mu         sync.Mutex
	enc        *FECEncoder
	blockStart uint32
	cnt        int
	lastAt     time.Time
}

func newRTFECSender() *fecSender {
	return &fecSender{enc: NewFECEncoder(fecK, fecM)}
}

func (s *fecSender) flushLocked() [][]byte {
	if s.cnt == 0 {
		return nil
	}
	var pkts [][]byte
	for s.cnt < fecK {
		seq := s.blockStart + uint32(s.cnt)
		pkts = append(pkts, s.enc.EncodeFEC(nil, seq, 0))
		s.cnt++
	}
	parityBase := s.blockStart + uint32(fecK)
	pkts = append(pkts, s.enc.GetParityPackets(parityBase, 0)...)
	s.blockStart += uint32(fecK + fecM)
	s.cnt = 0
	return pkts
}

func (s *fecSender) encode(payload []byte) [][]byte {
	if len(payload) > datagramMaxProtected || s.enc == nil {
		return [][]byte{append([]byte{markerRaw}, payload...)}
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var pkts [][]byte
	if s.cnt > 0 && time.Since(s.lastAt) >= fecBlockWait {
		pkts = s.flushLocked()
	}
	s.lastAt = time.Now()

	seq := s.blockStart + uint32(s.cnt)
	pkts = append(pkts, s.enc.EncodeFEC(payload, seq, 0))
	s.cnt++
	if s.cnt == fecK {
		parityBase := s.blockStart + uint32(fecK)
		pkts = append(pkts, s.enc.GetParityPackets(parityBase, 0)...)
		s.blockStart += uint32(fecK + fecM)
		s.cnt = 0
	}
	return pkts
}

type fecReceiver struct {
	mu       sync.Mutex
	dec      *FECDecoder
	received map[uint32][]byte
	firstAt  map[uint32]time.Time
}

func newRTFECReceiver() *fecReceiver {
	return &fecReceiver{
		dec:      NewFECDecoder(fecK, fecM),
		received: make(map[uint32][]byte),
		firstAt:  make(map[uint32]time.Time),
	}
}

func (r *fecReceiver) ingest(packet []byte) {
	if len(packet) < 9 || packet[0] != markerFEC {
		return
	}
	seq := binary.BigEndian.Uint32(packet[1:5])
	blockSize := uint32(fecK + fecM)
	blockStart := (seq / blockSize) * blockSize
	posInBlock := seq - blockStart

	r.mu.Lock()
	if _, ok := r.firstAt[blockStart]; !ok {
		r.firstAt[blockStart] = time.Now()
	}
	if posInBlock < uint32(fecK) {
		dataLen := binary.BigEndian.Uint16(packet[7:9])
		if int(dataLen)+9 <= len(packet) {
			r.received[seq] = append([]byte{}, packet[9:9+int(dataLen)]...)
		}
	}
	r.mu.Unlock()

	r.dec.DecodeFEC(packet, seq)
}

func (r *fecReceiver) sweep(deliver func([]byte)) {
	var due []uint32

	r.mu.Lock()
	now := time.Now()
	for bs, t := range r.firstAt {
		have := 0
		for i := uint32(0); i < uint32(fecK); i++ {
			if _, ok := r.received[bs+i]; ok {
				have++
			}
		}
		if have == fecK || now.Sub(t) >= fecBlockWait {
			due = append(due, bs)
		}
	}
	for _, bs := range due {
		delete(r.firstAt, bs)
	}
	r.mu.Unlock()

	for _, bs := range due {
		r.deliverBlock(bs, deliver)
	}
}

func (r *fecReceiver) deliverBlock(blockStart uint32, deliver func([]byte)) {
	r.mu.Lock()
	missing := false
	for i := uint32(0); i < uint32(fecK); i++ {
		if _, ok := r.received[blockStart+i]; !ok {
			missing = true
			break
		}
	}
	r.mu.Unlock()

	if missing {
		recovered := r.dec.Reconstruct(blockStart, fecK, fecM)
		r.mu.Lock()
		ri := 0
		for i := uint32(0); i < uint32(fecK); i++ {
			if _, ok := r.received[blockStart+i]; !ok && ri < len(recovered) {
				r.received[blockStart+i] = recovered[ri]
				ri++
			}
		}
		r.mu.Unlock()
	}

	r.mu.Lock()
	payloads := make([][]byte, 0, fecK)
	for i := uint32(0); i < uint32(fecK); i++ {
		if p, ok := r.received[blockStart+i]; ok && len(p) > 0 {
			payloads = append(payloads, p)
		}
		delete(r.received, blockStart+i)
	}
	for i := uint32(fecK); i < uint32(fecK+fecM); i++ {
		delete(r.received, blockStart+i)
	}
	r.mu.Unlock()

	r.dec.Forget(blockStart, fecK, fecM)

	for _, p := range payloads {
		deliver(p)
	}
}

func processIncoming(packet []byte, recv *fecReceiver, deliver func([]byte)) {
	if len(packet) == 0 {
		return
	}
	switch packet[0] {
	case markerRaw:
		deliver(append([]byte{}, packet[1:]...))
	case markerFEC:
		recv.ingest(packet)
	}
}

type DatagramClient struct {
	conn     *quicgo.Conn
	sender   *fecSender
	receiver *fecReceiver
	cancel   context.CancelFunc

	mu      sync.Mutex
	targets map[string]chan []byte
}

func NewDatagramClient(conn *quicgo.Conn) *DatagramClient {
	ctx, cancel := context.WithCancel(context.Background())
	c := &DatagramClient{
		conn:     conn,
		sender:   newRTFECSender(),
		receiver: newRTFECReceiver(),
		cancel:   cancel,
		targets:  make(map[string]chan []byte),
	}
	go c.receiveLoop(ctx)
	go c.sweepLoop(ctx)
	return c
}

func (c *DatagramClient) deliver(payload []byte) {
	host, port, data, ok := decodeAddr(payload)
	if !ok {
		return
	}
	key := net.JoinHostPort(host, strconv.Itoa(int(port)))
	c.mu.Lock()
	if ch := c.targets[key]; ch != nil {
		select {
		case ch <- data:
		default:
			traceLog.Warnw("rt_datagram_client_channel_full", "target", key)
		}
	}
	c.mu.Unlock()
}

func (c *DatagramClient) receiveLoop(ctx context.Context) {
	for {
		data, err := c.conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		processIncoming(data, c.receiver, c.deliver)
	}
}

func (c *DatagramClient) sweepLoop(ctx context.Context) {
	t := time.NewTicker(fecSweepEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.receiver.sweep(c.deliver)
		}
	}
}

func (c *DatagramClient) SendUDP(host string, port uint16, payload []byte) error {
	full := append(encodeAddr(host, port), payload...)
	for _, pkt := range c.sender.encode(full) {
		if err := c.conn.SendDatagram(pkt); err != nil {
			return err
		}
	}
	return nil
}

func (c *DatagramClient) RegisterTarget(host string, port uint16) (<-chan []byte, func()) {
	key := net.JoinHostPort(host, strconv.Itoa(int(port)))
	ch := make(chan []byte, 64)
	c.mu.Lock()
	c.targets[key] = ch
	c.mu.Unlock()
	var once sync.Once
	unregister := func() {
		once.Do(func() {
			c.mu.Lock()
			if c.targets[key] == ch {
				delete(c.targets, key)
				close(ch)
			}
			c.mu.Unlock()
		})
	}
	return ch, unregister
}

func (c *DatagramClient) Close() {
	c.cancel()
}

type serverSession struct {
	conn     *quicgo.Conn
	sender   *fecSender
	receiver *fecReceiver
	cancel   context.CancelFunc

	mu      sync.Mutex
	targets map[string]net.Conn
}

func newServerSession(conn *quicgo.Conn) *serverSession {
	ctx, cancel := context.WithCancel(context.Background())
	s := &serverSession{
		conn:     conn,
		sender:   newRTFECSender(),
		receiver: newRTFECReceiver(),
		cancel:   cancel,
		targets:  make(map[string]net.Conn),
	}
	go s.receiveLoop(ctx)
	go s.sweepLoop(ctx)
	return s
}

func (s *serverSession) receiveLoop(ctx context.Context) {
	for {
		data, err := s.conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		processIncoming(data, s.receiver, s.handlePayload)
	}
}

func (s *serverSession) sweepLoop(ctx context.Context) {
	t := time.NewTicker(fecSweepEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.receiver.sweep(s.handlePayload)
		}
	}
}

func (s *serverSession) handlePayload(payload []byte) {
	host, port, udpPayload, ok := decodeAddr(payload)
	if !ok {
		return
	}
	key := net.JoinHostPort(host, strconv.Itoa(int(port)))

	s.mu.Lock()
	uc, exists := s.targets[key]
	s.mu.Unlock()

	if !exists {
		// Dialing happens outside the lock: for a name it resolves first, and
		// holding the session lock through that stalls every other datagram on
		// this session — on the lane that exists for latency.
		ctx, cancel := context.WithTimeout(context.Background(), targetDialTimeout)
		fresh, err := (&net.Dialer{}).DialContext(ctx, "udp", key)
		cancel()
		if err != nil {
			traceLog.Infow("rt_datagram_target_dial_failed", "target", key, "err", err.Error())
			return
		}

		s.mu.Lock()
		if existing, raced := s.targets[key]; raced {
			s.mu.Unlock()
			fresh.Close()
			uc = existing
		} else {
			s.targets[key] = fresh
			s.mu.Unlock()
			uc = fresh
			traceLog.Infow("rt_datagram_target_dial", "target", key)
			go s.pumpTargetResponses(fresh, key, host, port)
		}
	}
	_, _ = uc.Write(udpPayload)
}

func (s *serverSession) pumpTargetResponses(uc net.Conn, key, host string, port uint16) {
	defer func() {
		if r := recover(); r != nil {
			traceLog.Errorf("PANIC in quic target pump: %v\n%s", r, debug.Stack())
		}
	}()
	defer func() {
		s.mu.Lock()
		delete(s.targets, key)
		s.mu.Unlock()
		uc.Close()
	}()
	buf := make([]byte, 65535)
	for {
		_ = uc.SetReadDeadline(time.Now().Add(udpTargetIdle))
		n, err := uc.Read(buf)
		if n > 0 {
			payload := append(encodeAddr(host, port), buf[:n]...)
			for _, pkt := range s.sender.encode(payload) {
				if serr := s.conn.SendDatagram(pkt); serr != nil {
					traceLog.Warnw("rt_datagram_target_send_failed", "target", key, "err", serr.Error())
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func (s *serverSession) Close() {
	s.cancel()
	s.mu.Lock()
	for _, uc := range s.targets {
		uc.Close()
	}
	s.mu.Unlock()
}

type connCtxKey struct{}

var ConnContextKey = connCtxKey{}

var (
	sessionsMu sync.Mutex
	sessions   = make(map[string]*serverSession)
)

func RegisterDatagramConn(sessionID []byte, conn *quicgo.Conn) {
	if conn == nil || len(sessionID) == 0 {
		return
	}
	key := string(sessionID)
	sessionsMu.Lock()
	if old, ok := sessions[key]; ok {
		old.Close()
	}
	sess := newServerSession(conn)
	sessions[key] = sess
	sessionsMu.Unlock()
	traceLog.Infow("rt_datagram_session_registered", "remote", conn.RemoteAddr().String())

	go func() {
		<-conn.Context().Done()
		sessionsMu.Lock()
		if sessions[key] == sess {
			delete(sessions, key)
		}
		sessionsMu.Unlock()
		sess.Close()
	}()
}
