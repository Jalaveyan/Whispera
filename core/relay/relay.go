package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nekoskin/whispera/common/buf"
	"github.com/nekoskin/whispera/common/dns"
	logger "github.com/nekoskin/whispera/common/log"
	"github.com/nekoskin/whispera/common/runtime/base"
	"github.com/nekoskin/whispera/common/runtime/interfaces"
	"github.com/nekoskin/whispera/common/runtime/registry"
	"github.com/nekoskin/whispera/core/protocol"

	xmux "github.com/sagernet/sing-mux"
	singlog "github.com/sagernet/sing/common/logger"
	singM "github.com/sagernet/sing/common/metadata"
	singN "github.com/sagernet/sing/common/network"
	"golang.org/x/net/proxy"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

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
	MaxStreams           int
	EnableTCP            bool
	EnableUDP            bool
	Debug                bool
	SafeMode             bool
	UpstreamProxy        string
	MaxConcurrentStreams int
	PaddingMaxSize       int
}

func DefaultConfig() *Config {
	return &Config{
		MaxStreams:           10000,
		EnableTCP:            true,
		EnableUDP:            true,
		Debug:                false,
		SafeMode:             true,
		MaxConcurrentStreams: 1024,
	}
}

func (c *Config) Validate() error {
	if c.MaxStreams <= 0 {
		c.MaxStreams = 10000
	}
	return nil
}

var udpCopyBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 2+65535)
		return &buf
	},
}

var dohResolver = dns.NewResolver(dns.DefaultConfig())

func lookupIPCached(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return dohResolver.Resolve(ctx, host)
}

const targetDialTimeout = 15 * time.Second

func dialTarget(dialer proxy.Dialer, network, host string, port uint16) (net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	ctx, cancel := context.WithTimeout(context.Background(), targetDialTimeout)
	defer cancel()
	dial := func(a string) (net.Conn, error) {
		if cd, ok := dialer.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, network, a)
		}
		return dialer.Dial(network, a)
	}
	if dialer != proxy.Direct || net.ParseIP(host) != nil {
		return dial(addr)
	}
	ips, err := lookupIPCached(host)
	if err != nil || len(ips) == 0 {
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

	streamSem chan struct{}

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

	limit := cfg.MaxConcurrentStreams
	if limit <= 0 {
		limit = 1024
	}
	s := &Server{
		Module:    base.NewModule(ModuleName, ModuleVersion, nil),
		config:    cfg,
		streamSem: make(chan struct{}, limit),
		log:       logger.Module("relay"),
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
	s.serveTunnel(conn, streamObf, true, nil)
}

func (s *Server) ServeTunnelRaw(conn net.Conn, streamObf bool) {
	s.serveTunnel(conn, streamObf, false, nil)
}

func (s *Server) ServeTunnelResilient(conn net.Conn, streamObf bool, secret []byte) {
	s.serveTunnel(conn, streamObf, true, secret)
}

func (s *Server) serveTunnel(conn net.Conn, streamObf bool, usePadding bool, secret []byte) {
	clientID := conn.RemoteAddr().String()
	defer conn.Close()
	s.runSession(conn, streamObf, usePadding, clientID)
}

func (s *Server) runSession(under net.Conn, streamObf bool, usePadding bool, clientID string) {
	traceID := atomic.AddUint64(&tunnelTraceSeq, 1)
	logger.Trace().Infow("serve_tunnel_enter",
		"trace_id", traceID,
		"client", clientID,
		"conn_type", fmt.Sprintf("%T", under),
		"stream_obf", streamObf,
		"use_padding", usePadding,
	)

	if tcpConn, ok := under.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	if protocol.StreamMuxEnabled() {
		s.serveStreamMux(under, clientID, traceID)
		return
	}
	s.handleProxyStream(traceID, clientID, under)
}

const (
	spliceRecordsToPad = 8
	frameForever       = -1
	// The largest record TLS 1.3 can put on the wire: 5 header + 16384 plaintext
	// + 1 content type + 16 AEAD tag. This was 16401 — the size of the body, not
	// of the record — so our biggest record was five bytes short of one a real
	// server sends, and real traffic has a visible peak exactly there (16406 is
	// its second most common size). Being unable to reach it is itself a tell.
	spliceWireTarget = 5 + 16384 + 1 + 16
	spliceMaxData    = spliceWireTarget - 5 - 2
	spliceMinPad     = 16
	spliceMaxPad     = 256
	naturalPad       = 2
)

type serverSpliceConn struct {
	net.Conn
	raw     net.Conn
	padLeft int
	closed  bool
	batch   []byte
	wmu     sync.Mutex
}

func (c *serverSpliceConn) Read(b []byte) (int, error) { return c.Conn.Read(b) }

func (c *serverSpliceConn) Write(b []byte) (int, error) { return c.writeShaped(b) }

func (c *serverSpliceConn) markClosed() {
	c.wmu.Lock()
	c.closed = true
	c.wmu.Unlock()
}

// Records go out in one write per call, not one write each. Once records are cut
// to the sizes real traffic uses — around 1387 bytes rather than the 16KB
// maximum — there are a dozen of them per read, and a syscall apiece cost 39% of
// throughput. What the wire carries is the same either way: TCP coalesces them
// into segments regardless of how many writes put them there.
// writeShaped frames the first padLeft records the way the client's splice
// decoder expects — a 0x17 TLS-application record whose body is a 2-byte data
// length followed by that many bytes — and then hands the rest straight to the
// socket. It carries no size shaping or filler: the record framing is the
// protocol (the client reads records until padLeft is spent), the sizes are not.
func (c *serverSpliceConn) writeShaped(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	sent := 0
	for len(b) > 0 && c.padLeft != 0 {
		n := len(b)
		if n > spliceMaxData {
			n = spliceMaxData
		}
		out := c.batch[:0]
		out = append(out, 0x17, 0x03, 0x03)
		out = binary.BigEndian.AppendUint16(out, uint16(2+n))
		out = binary.BigEndian.AppendUint16(out, uint16(n))
		out = append(out, b[:n]...)
		if _, err := c.raw.Write(out); err != nil {
			c.batch = out[:0]
			return sent, err
		}
		c.batch = out[:0]
		c.countTx(n)
		sent += n
		b = b[n:]
		if c.padLeft > 0 {
			c.padLeft--
		}
	}
	if len(b) > 0 {
		n, err := c.raw.Write(b)
		c.countTx(n)
		return sent + n, err
	}
	return sent, nil
}

func (c *serverSpliceConn) countTx(n int) {
	if n > 0 {
		if tc, ok := c.Conn.(interface{ CountTx(int) }); ok {
			tc.CountTx(n)
		}
	}
}

func (c *serverSpliceConn) spliceFrom(src net.Conn) (int64, error) {
	var total int64
	pre := make([]byte, spliceMaxData)
	defer c.markClosed()
	for c.padLeft != 0 {
		rn, rerr := src.Read(pre)
		if rn > 0 {
			n, werr := c.writeShaped(pre[:rn])
			total += int64(n)
			if werr != nil {
				return total, werr
			}
		}
		if rerr != nil {
			return total, rerr
		}
	}
	if dst, s := rawTCP(c.raw), rawTCP(src); dst != nil && s != nil {
		n, err := dst.ReadFrom(s)
		c.countTx(int(n))
		return total + n, err
	}
	n, err := io.Copy(c.raw, src)
	c.countTx(int(n))
	return total + n, err
}

// topUp waits a moment for the rest of what the origin is already sending.
//
// A read returns whatever has arrived, which for a 16KB record from a real site
// is the first few TCP segments of it. Shipping that as one record of ours, and
// the remainder as several more, is why our stream carried 232 records per
// connection where the origin's carried 63, why 39% of ours were under 64 bytes
// against the origin's 10%, and why we never emitted a full-size record at all
// while 14% of real ones are. The bytes we wait for are already in flight — this
// costs transmission time, not a round trip — and once the origin's own record
// boundaries survive, our sizes are its sizes.
func rawTCP(c net.Conn) *net.TCPConn {
	for c != nil {
		if tc, ok := c.(*net.TCPConn); ok {
			return tc
		}
		u, ok := c.(interface{ NetConn() net.Conn })
		if !ok {
			return nil
		}
		next := u.NetConn()
		if next == c {
			return nil
		}
		c = next
	}
	return nil
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

	dialer, outboundTag, blocked := h.s.resolveProxyDialer(network, addr, port)
	if blocked {
		return
	}
	targetAddr := net.JoinHostPort(addr, strconv.Itoa(int(port)))
	target, err := h.s.dialProxyTarget(outboundTag, network, targetAddr, addr, port, dialer)
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
		h.s.relayTCP(stream, target, resCh)
	}
	<-resCh
	<-resCh
}

func (s *Server) dialProxyTarget(outboundTag, network, targetAddr, addr string, port uint16, dialer proxy.Dialer) (net.Conn, error) {
	if outboundTag == "" {
		return dialTarget(dialer, network, addr, port)
	}
	s.mu.RLock()
	dialFn := s.outboundDial
	s.mu.RUnlock()
	if dialFn == nil {
		return dialTarget(dialer, network, addr, port)
	}
	dctx, dcancel := context.WithTimeout(context.Background(), targetDialTimeout)
	defer dcancel()
	return dialFn(dctx, outboundTag, network, targetAddr)
}

func (s *Server) resolveProxyDialer(network, addr string, port uint16) (proxy.Dialer, string, bool) {
	if network == "udp" {
		return proxy.Direct, "", false
	}
	s.routerMu.RLock()
	rtr := s.router
	s.routerMu.RUnlock()
	if rtr == nil {
		return s.proxyDialer, "", false
	}
	dstAddr, _ := net.ResolveTCPAddr("tcp", net.JoinHostPort(addr, strconv.Itoa(int(port))))
	dest, err := rtr.Route(context.Background(), &interfaces.Packet{DstAddr: dstAddr})
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
		defer target.Close()
		defer func() {
			if r := recover(); r != nil {
				s.log.Error("PANIC in UDP upstream copy: %v\n%s", r, debug.Stack())
			}
		}()
		bufp := udpCopyBufPool.Get().(*[]byte)
		defer udpCopyBufPool.Put(bufp)
		localBuf := *bufp
		hdr := localBuf[:2]
		data := localBuf[2:]
		var n int64
		for {
			if _, err := io.ReadFull(stream, hdr); err != nil {
				resCh <- copyResult{n, err, "up"}
				return
			}
			sz := int(binary.BigEndian.Uint16(hdr))
			if sz == 0 || sz > len(data) {
				resCh <- copyResult{n, fmt.Errorf("invalid UDP frame size %d", sz), "up"}
				return
			}
			if _, err := io.ReadFull(stream, data[:sz]); err != nil {
				resCh <- copyResult{n, err, "up"}
				return
			}
			if _, err := target.Write(data[:sz]); err != nil {
				resCh <- copyResult{n, err, "up"}
				return
			}
			n += int64(sz)
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
			if err != nil {
				resCh <- copyResult{n, err, "down"}
				return
			}
			binary.BigEndian.PutUint16(localBuf[:2], uint16(r))
			if _, err := stream.Write(localBuf[:2+r]); err != nil {
				resCh <- copyResult{n, err, "down"}
				return
			}
			n += int64(r)
		}
	}()
}

func (s *Server) relayTCP(stream, target net.Conn, resCh chan copyResult) {
	go func() {
		defer target.Close()
		defer func() {
			if r := recover(); r != nil {
				s.log.Error("PANIC in TCP upstream copy: %v\n%s", r, debug.Stack())
			}
		}()
		n, err := buf.Copy(buf.NewReader(stream), buf.NewWriter(target))
		if tc, ok := target.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		resCh <- copyResult{n, err, "up"}
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
	stream.Close()
	resCh <- copyResult{n, err, "down"}
}

func (s *Server) handleProxyStream(tunnelID uint64, clientID string, stream net.Conn) {
	defer stream.Close()
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("PANIC in handleProxyStream: %v\n%s", r, debug.Stack())
		}
	}()

	stream.SetReadDeadline(time.Now().Add(10 * time.Second))

	hdr := make([]byte, 3)
	if _, err := io.ReadFull(stream, hdr); err != nil {
		return
	}
	proto := hdr[0]
	splice := proto&protocol.SpliceProtoBit != 0 && protocol.SpliceEnabled()
	frameFull := proto&protocol.FullFrameProtoBit != 0
	proto &^= protocol.SpliceProtoBit | protocol.FullFrameProtoBit
	addrLen := binary.BigEndian.Uint16(hdr[1:3])
	if addrLen == 0 || addrLen > 255 {
		return
	}

	rest := make([]byte, int(addrLen)+2)
	if _, err := io.ReadFull(stream, rest); err != nil {
		return
	}
	addr := string(rest[:addrLen])
	port := binary.BigEndian.Uint16(rest[addrLen:])

	stream.SetReadDeadline(time.Time{})

	streamStart := time.Now()
	logger.Trace().Infow("proxy_stream_start",
		"trace_id", tunnelID,
		"client", clientID,
		"target", fmt.Sprintf("%s:%d", addr, port),
		"proto", fmt.Sprintf("0x%02x", proto),
	)

	network := "tcp"
	if proto == 0x11 {
		network = "udp"
	}

	dialer, outboundTag, blocked := s.resolveProxyDialer(network, addr, port)
	if blocked {
		return
	}

	targetAddr := net.JoinHostPort(addr, strconv.Itoa(int(port)))
	dialStart := time.Now()
	target, err := s.dialProxyTarget(outboundTag, network, targetAddr, addr, port, dialer)
	dialDur := time.Since(dialStart)
	if err != nil {
		logger.Trace().Warnw("proxy_stream_dial_fail",
			"trace_id", tunnelID,
			"target", targetAddr,
			"dial_ms", dialDur.Milliseconds(),
			"err", err.Error(),
			"err_type", fmt.Sprintf("%T", err),
		)
		return
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

	resCh := make(chan copyResult, 2)

	relayStream := stream
	if splice {
		if raw := protocol.NetConnOf(stream); raw != nil {
			left := spliceRecordsToPad
			if frameFull {
				left = frameForever
			}
			relayStream = &serverSpliceConn{Conn: stream, raw: raw, padLeft: left}
			logger.Trace().Infow("proxy_stream_splice", "trace_id", tunnelID, "target", targetAddr)
		}
	}

	if network == "udp" {
		s.relayUDP(stream, target, resCh)
	} else {
		s.relayTCP(relayStream, target, resCh)
	}
	r1 := <-resCh
	r2 := <-resCh
	var up, down int64
	var firstErr error
	var firstDir string
	for _, r := range [2]copyResult{r1, r2} {
		if r.dir == "up" {
			up = r.n
		} else {
			down = r.n
		}
		if firstErr == nil && r.err != nil && !errors.Is(r.err, io.EOF) {
			firstErr = r.err
			firstDir = r.dir
		}
	}
	dur := time.Since(streamStart)
	errField := ""
	if firstErr != nil && !isNormalConnClose(firstErr) && !errors.Is(firstErr, io.EOF) {
		errField = firstErr.Error()
	}
	logger.Trace().Infow("proxy_stream_done",
		"trace_id", tunnelID,
		"target", fmt.Sprintf("%s:%d", addr, port),
		"up", up,
		"down", down,
		"dur_ms", dur.Milliseconds(),
		"err_dir", firstDir,
		"err", errField,
	)
}

func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *Config
	if c, ok := cfg.(*Config); ok {
		config = c
	} else {
		config = DefaultConfig()
	}
	return New(config)
}
