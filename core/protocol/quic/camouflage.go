package quic

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	logger "github.com/nekoskin/whispera/common/log"
	"github.com/nekoskin/whispera/core/protocol/camo"
)

const (
	quicCamoTrustWindow  = time.Duration(camo.WindowTol*2+1) * time.Duration(camo.WindowSeconds) * time.Second
	quicCamoIdleTimeout  = 2 * time.Minute
	quicCamoCleanupEvery = time.Minute
)

type decoySession struct {
	upstream   net.Conn
	lastActive int64
	closeOnce  sync.Once
}

func newDecoySession(listenConn net.PacketConn, clientAddr net.Addr, target string) (*decoySession, error) {
	if target == "" {
		return nil, errors.New("whispera: quic decoy: no target")
	}
	upstream, err := (&net.Dialer{}).DialContext(context.Background(), "udp", target)
	if err != nil {
		return nil, err
	}
	s := &decoySession{}
	s.upstream = upstream
	atomic.StoreInt64(&s.lastActive, time.Now().UnixNano())
	go s.pump(listenConn, clientAddr)
	return s, nil
}

func (s *decoySession) pump(listenConn net.PacketConn, clientAddr net.Addr) {
	defer func() {
		if r := recover(); r != nil {
			traceLog.Errorf("PANIC in quic decoy pump: %v\n%s", r, debug.Stack())
		}
	}()
	defer s.Close()
	buf := make([]byte, 65535)
	for {
		_ = s.upstream.SetReadDeadline(time.Now().Add(quicCamoIdleTimeout))
		n, err := s.upstream.Read(buf)
		if n > 0 {
			atomic.StoreInt64(&s.lastActive, time.Now().UnixNano())
			if _, werr := listenConn.WriteTo(buf[:n], clientAddr); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (s *decoySession) forward(data []byte) {
	atomic.StoreInt64(&s.lastActive, time.Now().UnixNano())
	_, _ = s.upstream.Write(data)
}

func (s *decoySession) idleSince() time.Duration {
	return time.Since(time.Unix(0, atomic.LoadInt64(&s.lastActive)))
}

func (s *decoySession) Close() {
	s.closeOnce.Do(func() { s.upstream.Close() })
}

type camoConn struct {
	net.PacketConn
	keysFn     func() [][]byte
	bySelector func(random, keyShare []byte) bool
	rateAllow  func(remote string) bool
	decoyAddr  func(sni string) string

	mu            sync.Mutex
	realPeers     map[string]time.Time
	decoySessions map[string]*decoySession
	lastClean     time.Time
}

func (c *camoConn) authenticate(parsed *parsedQUICInitial) bool {
	if c.bySelector != nil && c.bySelector(parsed.random, parsed.keyShare) {
		return true
	}
	return camo.MarkerMatches(c.keysFn(), parsed.random, parsed.keyShare)
}

func NewCamoConn(inner net.PacketConn, keysFn func() [][]byte, bySelector func(random, keyShare []byte) bool, decoyAddr func(string) string, rateAllow func(string) bool) *camoConn {
	return &camoConn{
		PacketConn:    inner,
		keysFn:        keysFn,
		bySelector:    bySelector,
		rateAllow:     rateAllow,
		decoyAddr:     decoyAddr,
		realPeers:     make(map[string]time.Time),
		decoySessions: make(map[string]*decoySession),
		lastClean:     time.Now(),
	}
}

func parseInitialSafely(packet []byte) (parsed *parsedQUICInitial, err error) {
	defer func() {
		if r := recover(); r != nil {
			parsed, err = nil, fmt.Errorf("whispera: quic initial parse panicked: %v", r)
			traceLog.Errorw("quic_initial_parse_panic", "err", fmt.Sprint(r), "size", len(packet))
		}
	}()
	return parseQUICInitialClientHello(packet)
}

func (c *camoConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		key := addr.String()

		c.mu.Lock()
		if exp, ok := c.realPeers[key]; ok {
			if time.Now().Before(exp) {
				c.realPeers[key] = time.Now().Add(quicCamoTrustWindow)
				c.mu.Unlock()
				return n, addr, nil
			}
			delete(c.realPeers, key)
		}
		sess, isDecoy := c.decoySessions[key]
		c.cleanupLocked()
		c.mu.Unlock()

		if isDecoy {
			sess.forward(p[:n])
			continue
		}

		parsed, perr := parseInitialSafely(p[:n])
		if perr == nil && c.authenticate(parsed) {
			c.mu.Lock()
			c.realPeers[key] = time.Now().Add(quicCamoTrustWindow)
			c.mu.Unlock()
			traceLog.Infow("quic_camo_authenticated", "remote", key)
			continue
		}

		if c.rateAllow != nil && !c.rateAllow(key) {
			traceLog.Infow("quic_camo_relay_decoy_throttled", "remote", key)
			continue
		}
		sni := ""
		if parsed != nil {
			sni = parsed.sni
		}
		target := c.decoyAddr(sni)
		newSess, serr := newDecoySession(c.PacketConn, addr, target)
		if serr != nil {
			continue
		}
		traceLog.Infow("quic_camo_relay_decoy", "remote", key, "sni", sni, "target", target)
		c.mu.Lock()
		c.decoySessions[key] = newSess
		c.mu.Unlock()
		newSess.forward(p[:n])
	}
}

func (c *camoConn) cleanupLocked() {
	now := time.Now()
	if now.Sub(c.lastClean) < quicCamoCleanupEvery {
		return
	}
	c.lastClean = now
	for k, exp := range c.realPeers {
		if now.After(exp) {
			delete(c.realPeers, k)
		}
	}
	for k, sess := range c.decoySessions {
		if sess.idleSince() > quicCamoIdleTimeout {
			sess.Close()
			delete(c.decoySessions, k)
		}
	}
}

var traceLog = logger.Trace()
