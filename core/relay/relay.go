package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nekoskin/whispera/common/buf"
	"github.com/nekoskin/whispera/common/cache"
	logger "github.com/nekoskin/whispera/common/log"
	"github.com/nekoskin/whispera/common/runtime/base"
	"github.com/nekoskin/whispera/common/runtime/interfaces"
	"github.com/nekoskin/whispera/core/protocol"

	xmux "github.com/sagernet/sing-mux"
	singlog "github.com/sagernet/sing/common/logger"
	singM "github.com/sagernet/sing/common/metadata"
	singN "github.com/sagernet/sing/common/network"
	"golang.org/x/net/proxy"
)

func isNormalConnClose(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "read/write on closed pipe") ||
		strings.Contains(msg, "closed pipe") ||
		strings.Contains(msg, "forcibly closed")
}

const (
	ModuleName    = "relay.server"
	ModuleVersion = "1.0.0"
)

type ResponseWriter interface {
	Write(data []byte) error
	RemoteAddr() net.Addr
}
type Config struct {
	EnableTCP     bool
	EnableUDP     bool
	Debug         bool
	UpstreamProxy string
}

func DefaultConfig() *Config {
	return &Config{
		EnableTCP: true,
		EnableUDP: true,
		Debug:     false,
	}
}

func (c *Config) Validate() error {
	return nil
}

var udpCopyBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 2+65535)
		return &buf
	},
}

// The server sits in a datacentre, not behind the censor, so the system
// resolver is the right one to ask — it answers in microseconds where going out
// to 8.8.8.8, and falling back to DoH when that is unreachable, spent whole
// seconds before the stream had dialed anything.
//
// It gets a cache of our own on top. systemd-resolved honors the TTL to the
// letter, and a CDN record lives thirty seconds, so on a real server it was
// missing three times out of four — every miss a query on the path of opening a
// stream. Holding an answer a little past its TTL costs at most a stale address
// for a minute; the routing decision it feeds is coarse enough for that.
const (
	routeLookupWait = 300 * time.Millisecond
	routeCacheTTL   = time.Minute
	routeCacheSize  = 4096
)

var routeCache = cache.NewLRUCache[[]net.IP](routeCacheSize)

func lookupIPCached(host string) ([]net.IP, error) {
	if ips, err := routeCache.Get(context.Background(), host); err == nil && len(ips) > 0 {
		return ips, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), routeLookupWait)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, len(addrs))
	for i, a := range addrs {
		ips[i] = a.IP
	}
	_ = routeCache.Set(context.Background(), host, ips, routeCacheTTL)
	return ips, nil
}

// An address that has not answered in eight seconds will not answer in fifteen:
// 99% of dials finish inside 100 ms, and the ones that time out are blocked
// routes. The stream — and the person waiting on it — is held for the whole
// budget, so it is worth keeping short.
const targetDialTimeout = 8 * time.Second

// targetIPs resolves a name for the router to decide on. Only the router needs
// this: dialing by name lets the system resolver do the work, with its own cache
// and its own happy-eyeballs, and it answers in microseconds where ours went to
// 8.8.8.8 and, when that is unreachable, sat in a DoH fallback until the 3s
// budget ran out — once per stream, before a single byte moved.
func targetIPs(host string) []net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}
	}
	ips, err := lookupIPCached(host)
	if err != nil {
		return nil
	}
	return ips
}

// firstTCPAddr returns a net.Addr, not a *net.TCPAddr: a nil pointer put in an
// interface stops being nil, so every "if addr != nil" downstream would let it
// through and route on the string "<nil>" — one cache entry shared by every
// name that failed to resolve.
func firstTCPAddr(ips []net.IP, port uint16) net.Addr {
	if len(ips) == 0 {
		return nil
	}
	return &net.TCPAddr{IP: ips[0], Port: int(port)}
}

func dialTarget(dialer proxy.Dialer, network, host string, port uint16, ips []net.IP) (net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	ctx, cancel := context.WithTimeout(context.Background(), targetDialTimeout)
	defer cancel()
	dial := func(a string) (net.Conn, error) {
		if cd, ok := dialer.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, network, a)
		}
		return dialer.Dial(network, a)
	}
	if dialer != proxy.Direct || net.ParseIP(host) != nil || len(ips) == 0 {
		return dial(addr)
	}
	var lastErr error
	for _, ip := range preferIPv6(ips) {
		conn, derr := dial(net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
	}
	return nil, lastErr
}

func preferIPv6(ips []net.IP) []net.IP {
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip.To4() == nil {
			out = append(out, ip)
		}
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			out = append(out, ip)
		}
	}
	return out
}

type Server struct {
	*base.Module
	config      *Config
	proxyDialer proxy.Dialer
	router      interfaces.Router
	routerMu    sync.RWMutex

	outboundDial func(ctx context.Context, tag, network, addr string) (net.Conn, error)

	log *logger.Logger
	mu  sync.RWMutex
}

type copyResult struct {
	n   int64
	err error
	dir string
}

func New(cfg *Config) (*Server, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	s := &Server{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: cfg,
		log:    logger.Module("relay"),
	}

	s.proxyDialer = proxy.Direct
	if cfg.UpstreamProxy != "" {
		u, err := url.Parse(cfg.UpstreamProxy)
		if err != nil {
			s.log.Error("Invalid upstream proxy URL: %v", err)
			return nil, fmt.Errorf("invalid upstream proxy URL: %v", err)
		}
		dialer, err := proxy.FromURL(u, proxy.Direct)
		if err != nil {
			s.log.Error("Failed to create proxy dialer: %v", err)
			return nil, fmt.Errorf("failed to create proxy dialer: %v", err)
		}
		s.proxyDialer = dialer
	}

	return s, nil
}

func (s *Server) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := s.Module.Init(ctx, cfg); err != nil {
		return err
	}
	return nil
}

func (s *Server) Start() error {
	if err := s.Module.Start(); err != nil {
		return err
	}

	return nil
}

func (s *Server) Stop() error {
	return s.Module.Stop()
}

func (s *Server) SetRouter(r interfaces.Router) {
	s.routerMu.Lock()
	s.router = r
	s.routerMu.Unlock()
}

func (s *Server) SetOutboundDial(fn func(ctx context.Context, tag, network, addr string) (net.Conn, error)) {
	s.mu.Lock()
	s.outboundDial = fn
	s.mu.Unlock()
}

func (s *Server) SetProxyDialer(d proxy.Dialer) {
	s.mu.Lock()
	s.proxyDialer = d
	s.mu.Unlock()
}

func (s *Server) HealthCheck() interfaces.HealthStatus {
	return s.Module.HealthCheck()
}

var tunnelTraceSeq uint64

func (s *Server) ServeTunnel(conn net.Conn, streamObf bool) {
	s.serveTunnel(conn, streamObf, nil)
}

func (s *Server) ServeTunnelRaw(conn net.Conn, streamObf bool) {
	s.serveTunnel(conn, streamObf, nil)
}

func (s *Server) ServeTunnelResilient(conn net.Conn, streamObf bool, secret []byte) {
	s.serveTunnel(conn, streamObf, secret)
}

func (s *Server) serveTunnel(conn net.Conn, streamObf bool, secret []byte) {
	clientID := conn.RemoteAddr().String()
	defer conn.Close()
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("PANIC in tunnel session for %s: %v\n%s", clientID, r, debug.Stack())
		}
	}()
	s.runSession(conn, streamObf, clientID)
}

func (s *Server) runSession(under net.Conn, streamObf bool, clientID string) {
	traceID := atomic.AddUint64(&tunnelTraceSeq, 1)
	logger.Trace().Infow("serve_tunnel_enter",
		"trace_id", traceID,
		"client", clientID,
		"conn_type", fmt.Sprintf("%T", under),
		"stream_obf", streamObf,
	)

	if tcpConn := buf.RawTCP(under); tcpConn != nil {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	if protocol.StreamMuxEnabled() {
		s.serveStreamMux(under, clientID, traceID)
		return
	}
	// One padding budget for the whole connection: the streams that follow are
	// requests on an established socket, and a fresh burst of padded records
	// after each of them is a pattern of its own.
	pad := protocol.NewShapeBudget()
	wait := proxyHeaderWait
	for {
		if !s.handleProxyStream(traceID, clientID, under, wait, pad) {
			return
		}
		wait = 0
		traceID = atomic.AddUint64(&tunnelTraceSeq, 1)
	}
}

const (
	proxyHeaderWait = 10 * time.Second

	// Switching to raw costs the connection: a stream that leaves framing can
	// never be handed back to the pool, and reopening one is two round trips —
	// about 3 MB of transfer at the rates and latencies we see. Below that the
	// kernel path saves less CPU than the handshake costs, so ordinary pages,
	// images and video chunks stay framed and keep their connection.
	spliceAfterBytes = 4 << 20
	targetDrainWait  = 5 * time.Second
	// Read as much as the copy path does elsewhere. Reading one record's worth at
	// a time meant four syscalls where one would do, and on short answers — the
	// whole of a page — that is the entire transfer.
	spliceReadBuf = 64 << 10
)

type serverSpliceConn struct {
	net.Conn
	up   *protocol.FramedConn
	down *protocol.FramedConn
	raw  net.Conn
	left int64
}

func (c *serverSpliceConn) Read(b []byte) (int, error) { return c.up.Read(b) }

func (c *serverSpliceConn) Write(b []byte) (int, error) { return c.down.Write(b) }

func (c *serverSpliceConn) countTx(n int) {
	if n > 0 {
		if tc, ok := c.Conn.(interface{ CountTx(int) }); ok {
			tc.CountTx(n)
		}
	}
}

func (c *serverSpliceConn) spliceFrom(src net.Conn) (int64, error) {
	var total int64
	// One 64K buffer per stream is 64 MB of garbage per thousand streams, and
	// the pool already holds buffers of exactly this size.
	pb := buf.New()
	defer pb.Release()
	pre := pb.Extend(spliceReadBuf)
	for c.left > 0 {
		rn, rerr := src.Read(pre)
		if rn > 0 {
			n, werr := c.down.Write(pre[:rn])
			total += int64(n)
			c.left -= int64(n)
			if werr != nil {
				return total, werr
			}
		}
		if rerr != nil {
			return total, rerr
		}
	}
	if err := c.down.SwitchRaw(); err != nil {
		return total, err
	}
	if dst, s := buf.RawTCP(c.raw), buf.RawTCP(src); dst != nil && s != nil {
		n, err := dst.ReadFrom(s)
		c.countTx(int(n))
		return total + n, err
	}
	n, err := io.Copy(c.raw, src)
	c.countTx(int(n))
	return total + n, err
}

func (s *Server) serveStreamMux(under net.Conn, clientID string, traceID uint64) {
	svc, err := xmux.NewService(xmux.ServiceOptions{
		NewStreamContext: func(ctx context.Context, _ net.Conn) context.Context { return ctx },
		Logger:           singlog.NOP(),
		HandlerEx:        &muxHandler{s: s, clientID: clientID, traceID: traceID},
	})
	if err != nil {
		s.log.Error("[T%d] stream-mux init for %s: %v", traceID, clientID, err)
		return
	}
	svc.NewConnectionEx(context.Background(), under, singM.Socksaddr{}, singM.Socksaddr{}, nil)
}

type muxHandler struct {
	s        *Server
	clientID string
	traceID  uint64
}

func (h *muxHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, dest singM.Socksaddr, onClose singN.CloseHandlerFunc) {
	h.serveStream(conn, dest)
	if onClose != nil {
		onClose(nil)
	}
}

func (h *muxHandler) NewPacketConnectionEx(ctx context.Context, conn singN.PacketConn, source, dest singM.Socksaddr, onClose singN.CloseHandlerFunc) {
	conn.Close()
	if onClose != nil {
		onClose(nil)
	}
}

func (h *muxHandler) serveStream(stream net.Conn, dest singM.Socksaddr) {
	defer stream.Close()
	defer func() {
		if r := recover(); r != nil {
			h.s.log.Error("PANIC in stream-mux stream: %v\n%s", r, debug.Stack())
		}
	}()

	var pb [1]byte
	if _, err := io.ReadFull(stream, pb[:]); err != nil {
		return
	}
	network := "tcp"
	if pb[0] == 0x11 {
		network = "udp"
	}

	addr := dest.Fqdn
	if addr == "" {
		addr = dest.Addr.String()
	}
	port := dest.Port

	ips := h.s.routeIPs(addr)
	dialer, outboundTag, blocked := h.s.resolveProxyDialer(network, addr, port, ips)
	if blocked {
		return
	}
	targetAddr := net.JoinHostPort(addr, strconv.Itoa(int(port)))
	target, err := h.s.dialProxyTarget(outboundTag, network, targetAddr, addr, port, dialer, ips)
	if err != nil {
		logger.Trace().Warnw("stream_mux_dial_fail", "trace_id", h.traceID, "target", targetAddr, "err", err.Error())
		return
	}
	defer target.Close()

	if tc, ok := target.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(45 * time.Second)
	}

	resCh := make(chan copyResult, 2)
	if network == "udp" {
		h.s.relayUDP(stream, target, resCh)
	} else {
		h.s.relayTCP(stream, target, resCh, nil)
	}
	<-resCh
	<-resCh
}

func (s *Server) dialProxyTarget(outboundTag, network, targetAddr, addr string, port uint16, dialer proxy.Dialer, ips []net.IP) (net.Conn, error) {
	if outboundTag == "" {
		return dialTarget(dialer, network, addr, port, ips)
	}
	s.mu.RLock()
	dialFn := s.outboundDial
	s.mu.RUnlock()
	if dialFn == nil {
		return dialTarget(dialer, network, addr, port, ips)
	}
	dctx, dcancel := context.WithTimeout(context.Background(), targetDialTimeout)
	defer dcancel()
	return dialFn(dctx, outboundTag, network, targetAddr)
}

// routeIPs resolves only when a router is there to route on the answer, and
// only when its rules actually look at addresses. A ruleset that matches on
// ports alone needs no lookup at all.
func (s *Server) routeIPs(host string) []net.IP {
	s.routerMu.RLock()
	rtr := s.router
	s.routerMu.RUnlock()
	if rtr == nil {
		return nil
	}
	if byAddr, ok := rtr.(interface{ RoutesOnAddress() bool }); ok && !byAddr.RoutesOnAddress() {
		return nil
	}
	return targetIPs(host)
}

func (s *Server) resolveProxyDialer(network, addr string, port uint16, ips []net.IP) (proxy.Dialer, string, bool) {
	if network == "udp" {
		return proxy.Direct, "", false
	}
	s.routerMu.RLock()
	rtr := s.router
	s.routerMu.RUnlock()
	if rtr == nil {
		return s.proxyDialer, "", false
	}
	dest, err := rtr.Route(context.Background(), &interfaces.Packet{DstAddr: firstTCPAddr(ips, port)})
	if err != nil {
		return s.proxyDialer, "", false
	}
	switch dest.Type {
	case interfaces.DestinationDirect:
		return proxy.Direct, "", false
	case interfaces.DestinationBlock:
		return nil, "", true
	default:
		return s.proxyDialer, dest.Tag, false
	}
}

func (s *Server) relayUDP(stream, target net.Conn, resCh chan copyResult) {
	go func() {
		res := copyResult{dir: "up"}
		defer func() {
			if r := recover(); r != nil {
				s.log.Error("PANIC in UDP upstream copy: %v\n%s", r, debug.Stack())
				if res.err == nil {
					res.err = fmt.Errorf("panic in UDP upstream copy: %v", r)
				}
			}
			resCh <- res
		}()
		defer target.Close()
		bufp := udpCopyBufPool.Get().(*[]byte)
		defer udpCopyBufPool.Put(bufp)
		localBuf := *bufp
		hdr := localBuf[:2]
		data := localBuf[2:]
		for {
			if _, err := io.ReadFull(stream, hdr); err != nil {
				res.err = err
				return
			}
			sz := int(binary.BigEndian.Uint16(hdr))
			if sz == 0 || sz > len(data) {
				res.err = fmt.Errorf("invalid UDP frame size %d", sz)
				return
			}
			if _, err := io.ReadFull(stream, data[:sz]); err != nil {
				res.err = err
				return
			}
			if _, err := target.Write(data[:sz]); err != nil {
				res.err = err
				return
			}
			res.n += int64(sz)
		}
	}()
	func() {
		defer stream.Close()
		bufp := udpCopyBufPool.Get().(*[]byte)
		defer udpCopyBufPool.Put(bufp)
		localBuf := *bufp
		var n int64
		for {
			r, err := target.Read(localBuf[2:])
			if r > 0 {
				binary.BigEndian.PutUint16(localBuf[:2], uint16(r))
				if _, werr := stream.Write(localBuf[:2+r]); werr != nil {
					resCh <- copyResult{n, werr, "down"}
					return
				}
				n += int64(r)
			}
			if err != nil {
				resCh <- copyResult{n, err, "down"}
				return
			}
		}
	}()
}

// relayTCP moves the stream both ways. down reports the end of the answer as
// soon as the origin has finished, so the caller can say so on the wire without
// waiting for the client's own marker — that wait cost a round trip after every
// byte had already arrived, and the connection sat out of the pool for it.
func (s *Server) relayTCP(stream, target net.Conn, resCh chan copyResult, downDone func()) {
	go func() {
		res := copyResult{dir: "up"}
		defer func() {
			if r := recover(); r != nil {
				s.log.Error("PANIC in TCP upstream copy: %v\n%s", r, debug.Stack())
				if res.err == nil {
					res.err = fmt.Errorf("panic in TCP upstream copy: %v", r)
				}
			}
			if res.err != nil {
				target.Close()
			}
			resCh <- res
		}()
		res.n, res.err = buf.Copy(buf.NewReader(stream), buf.NewWriter(target))
		if res.err != nil {
			return
		}
		// Half-close instead of Close: the origin answers our FIN with its own,
		// which ends the downstream copy cleanly. Closing outright made that copy
		// fail with "use of closed network connection", and a stream whose copy
		// ended in an error is never handed back to the pool.
		if tc, ok := target.(*net.TCPConn); ok {
			tc.CloseWrite()
			tc.SetReadDeadline(time.Now().Add(targetDrainWait))
		} else {
			target.Close()
		}
	}()

	var n int64
	var err error
	if sc, ok := stream.(*serverSpliceConn); ok {
		n, err = sc.spliceFrom(target)
	} else {
		n, err = buf.Copy(buf.NewReader(target), buf.NewWriter(stream))
	}
	if tc, ok := stream.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
	if downDone != nil && err == nil {
		downDone()
	}
	resCh <- copyResult{n, err, "down"}
}

type proxyStreamHeader struct {
	proto     byte
	splice    bool
	keepAlive bool
	addr      string
	port      uint16
}

func (h proxyStreamHeader) target() string {
	return net.JoinHostPort(h.addr, strconv.Itoa(int(h.port)))
}

func (h proxyStreamHeader) network() string {
	if h.proto == 0x11 {
		return "udp"
	}
	return "tcp"
}

func readProxyStreamHeader(stream net.Conn, wait time.Duration) (proxyStreamHeader, bool) {
	if wait > 0 {
		stream.SetReadDeadline(time.Now().Add(wait))
		defer stream.SetReadDeadline(time.Time{})
	}

	hdr := make([]byte, 3)
	if _, err := io.ReadFull(stream, hdr); err != nil {
		return proxyStreamHeader{}, false
	}
	addrLen := binary.BigEndian.Uint16(hdr[1:3])
	if addrLen == 0 || addrLen > 255 {
		return proxyStreamHeader{}, false
	}

	rest := make([]byte, int(addrLen)+2)
	if _, err := io.ReadFull(stream, rest); err != nil {
		return proxyStreamHeader{}, false
	}

	proto := hdr[0]
	return proxyStreamHeader{
		proto:     proto &^ (protocol.SpliceProtoBit | protocol.KeepAliveProtoBit),
		splice:    proto&protocol.SpliceProtoBit != 0 && protocol.SpliceEnabled(),
		keepAlive: proto&protocol.KeepAliveProtoBit != 0,
		addr:      string(rest[:addrLen]),
		port:      binary.BigEndian.Uint16(rest[addrLen:]),
	}, true
}

func spliceWrap(stream net.Conn, framed *protocol.FramedConn, h proxyStreamHeader, tunnelID uint64, targetAddr string, pad *protocol.ShapeBudget) (net.Conn, *protocol.FramedConn) {
	if !h.splice {
		return framed, framed
	}
	raw := protocol.NetConnOf(stream)
	if raw == nil {
		return framed, framed
	}
	// The client is already reading from the raw socket, so the framing has to
	// move there either way — that part is agreed in the header and cannot be
	// declined here. What can be declined is dropping the framing altogether:
	// that is what costs the connection, and it only pays for itself while the
	// CPU is the scarce resource.
	left := int64(math.MaxInt64)
	if cpuBusy() {
		left = spliceAfterBytes
	}
	down := protocol.NewFramedConn(raw, pad)
	logger.Trace().Infow("proxy_stream_splice", "trace_id", tunnelID, "target", targetAddr, "to_raw_after", left)
	return &serverSpliceConn{Conn: stream, up: framed, down: down, raw: raw, left: left}, down
}

func collectCopyResults(resCh chan copyResult) (up, down int64, firstErr error, firstDir string) {
	for i := 0; i < 2; i++ {
		r := <-resCh
		if r.dir == "up" {
			up = r.n
		} else {
			down = r.n
		}
		if firstErr == nil && r.err != nil && !errors.Is(r.err, io.EOF) {
			firstErr, firstDir = r.err, r.dir
		}
	}
	return up, down, firstErr, firstDir
}

func (s *Server) handleProxyStream(tunnelID uint64, clientID string, stream net.Conn, wait time.Duration, pad *protocol.ShapeBudget) (reusable bool) {
	defer func() {
		if !reusable {
			stream.Close()
		}
	}()
	defer func() {
		if r := recover(); r != nil {
			reusable = false
			s.log.Error("PANIC in handleProxyStream: %v\n%s", r, debug.Stack())
		}
	}()

	h, ok := readProxyStreamHeader(stream, wait)
	if !ok {
		return false
	}
	targetAddr := h.target()
	network := h.network()

	streamStart := time.Now()
	logger.Trace().Infow("proxy_stream_start",
		"trace_id", tunnelID,
		"client", clientID,
		"target", targetAddr,
		"proto", fmt.Sprintf("0x%02x", h.proto),
	)

	ips := s.routeIPs(h.addr)
	dialer, outboundTag, blocked := s.resolveProxyDialer(network, h.addr, h.port, ips)
	if blocked {
		return false
	}

	dialStart := time.Now()
	target, err := s.dialProxyTarget(outboundTag, network, targetAddr, h.addr, h.port, dialer, ips)
	dialDur := time.Since(dialStart)
	if err != nil {
		logger.Trace().Warnw("proxy_stream_dial_fail",
			"trace_id", tunnelID,
			"target", targetAddr,
			"dial_ms", dialDur.Milliseconds(),
			"err", err.Error(),
			"err_type", fmt.Sprintf("%T", err),
		)
		return false
	}
	defer target.Close()
	logger.Trace().Infow("proxy_stream_dial_ok",
		"trace_id", tunnelID,
		"target", targetAddr,
		"dial_ms", dialDur.Milliseconds(),
	)

	if tcpTarget, ok := target.(*net.TCPConn); ok {
		tcpTarget.SetKeepAlive(true)
		tcpTarget.SetKeepAlivePeriod(45 * time.Second)
	}

	var framed *protocol.FramedConn
	if h.keepAlive {
		framed = protocol.NewFramedConn(stream, pad)
	}

	var downFramed *protocol.FramedConn
	resCh := make(chan copyResult, 2)
	switch {
	case network == "udp" && framed != nil:
		// UDP streams are framed too, so they end the same way and their
		// connection goes back to the pool. Leaving downFramed nil here had the
		// server close a connection the client had already pooled, and the next
		// stream to pick it up found it dead.
		downFramed = framed
		s.relayUDP(framed, target, resCh)
	case network == "udp":
		s.relayUDP(stream, target, resCh)
	case framed != nil:
		var wrapped net.Conn
		wrapped, downFramed = spliceWrap(stream, framed, h, tunnelID, targetAddr, pad)
		end := downFramed
		s.relayTCP(wrapped, target, resCh, func() { _ = end.EndStream() })
	default:
		s.relayTCP(stream, target, resCh, nil)
	}

	up, down, firstErr, firstDir := collectCopyResults(resCh)
	errField := ""
	if firstErr != nil && !isNormalConnClose(firstErr) && !errors.Is(firstErr, io.EOF) {
		errField = firstErr.Error()
	}
	logger.Trace().Infow("proxy_stream_done",
		"trace_id", tunnelID,
		"target", targetAddr,
		"up", up,
		"down", down,
		"dur_ms", time.Since(streamStart).Milliseconds(),
		"err_dir", firstDir,
		"err", errField,
	)

	if downFramed != nil {
		_ = downFramed.EndStream()
		reusable = framed.StreamDone() && !downFramed.SwitchedRaw() && firstErr == nil
	}
	return reusable
}
