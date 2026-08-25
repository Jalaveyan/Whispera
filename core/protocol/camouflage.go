package protocol

import (
	"context"
	"errors"
	"fmt"
	"github.com/nekoskin/whispera/core/protocol/fingerprint"
	"io"
	"net"
	"net/url"
	"runtime/debug"
	"slices"
	"sync"
	"time"

	"github.com/nekoskin/whispera/core/protocol/camo"

	utls "github.com/refraction-networking/utls"
)

var errHelloIncomplete = errors.New("whispera: ClientHello incomplete")

func readFullIdle(conn net.Conn, buf []byte, idle time.Duration) (int, error) {
	n := 0
	for n < len(buf) {
		if err := conn.SetReadDeadline(time.Now().Add(idle)); err != nil {
			return n, err
		}
		m, err := conn.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

const (
	camoWindowSeconds = authWindowSeconds
	camoPeekTimeout   = 4 * time.Second
	camoMaxHandshake  = 8192
	camoDialTimeout   = 5 * time.Second
)

type peekedHello struct {
	raw      []byte
	random   []byte
	sni      string
	keyShare []byte
}

// Room for a ClientHello: the biggest ones we see, with post-quantum key
// shares, land just under 2 KB.
const camoHelloHint = 2048

func peekClientHello(conn net.Conn) (*peekedHello, error) {
	defer conn.SetReadDeadline(time.Time{})

	// A ClientHello arrives in one record and fits here, so the whole peek costs
	// one allocation. Growing from nil reallocated several times per connection,
	// and the record body was copied twice on top of that.
	raw := make([]byte, 0, camoHelloHint)
	var hs []byte

	for {
		var hdr [5]byte
		if _, err := readFullIdle(conn, hdr[:], camoPeekTimeout); err != nil {
			return &peekedHello{raw: raw}, fmt.Errorf("%w: %v", errHelloIncomplete, err)
		}
		raw = append(raw, hdr[:]...)
		if hdr[0] != 0x16 {
			return &peekedHello{raw: raw}, fmt.Errorf("whispera: not a TLS handshake record")
		}
		recLen := int(hdr[3])<<8 | int(hdr[4])
		if recLen <= 0 || recLen > 16384 {
			return &peekedHello{raw: raw}, fmt.Errorf("whispera: invalid TLS record length")
		}
		raw = slices.Grow(raw, recLen)
		body := raw[len(raw) : len(raw)+recLen]
		if _, err := readFullIdle(conn, body, camoPeekTimeout); err != nil {
			return &peekedHello{raw: raw}, fmt.Errorf("%w: %v", errHelloIncomplete, err)
		}
		raw = raw[:len(raw)+recLen]
		if hs == nil {
			// Capped at its own length: appending to it later must copy, not
			// write back into raw over the record header that follows.
			hs = body[:len(body):len(body)]
		} else {
			hs = append(hs, body...)
		}

		if len(hs) > camoMaxHandshake {
			return &peekedHello{raw: raw}, fmt.Errorf("whispera: ClientHello too large")
		}
		if len(hs) < 4 {
			continue
		}
		if hs[0] != 0x01 {
			return &peekedHello{raw: raw}, fmt.Errorf("whispera: not a ClientHello")
		}
		bodyLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
		want := 4 + bodyLen
		if len(hs) < want {
			continue
		}
		msg := utls.UnmarshalClientHello(hs[:want])
		if msg == nil {
			return &peekedHello{raw: raw}, fmt.Errorf("whispera: failed to parse ClientHello")
		}
		return &peekedHello{
			raw:      raw,
			random:   msg.Random,
			sni:      msg.ServerName,
			keyShare: camo.ExtractX25519KeyShare(msg.KeyShares),
		}, nil
	}
}

type prefixConn struct {
	net.Conn
	prefix []byte
	off    int

	knownUser string
	knownPSK  []byte
}

func (c *prefixConn) NetConn() net.Conn { return c.Conn }

func (c *prefixConn) Read(b []byte) (int, error) {
	if c.off < len(c.prefix) {
		n := copy(b, c.prefix[c.off:])
		c.off += n
		return n, nil
	}
	return c.Conn.Read(b)
}

// relayToOrigin hands the connection to the site we hide behind. It reports
// whether it took the connection over: when it could not, the caller still owes
// the peer an answer.
func relayToOrigin(conn net.Conn, raw []byte, addr string) bool {
	if addr == "" {
		return false
	}
	dialCtx, cancel := context.WithTimeout(context.Background(), camoDialTimeout)
	defer cancel()
	upstream, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	defer upstream.Close()

	if len(raw) > 0 {
		if _, err := upstream.Write(raw); err != nil {
			return true
		}
	}

	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, upstream); done <- struct{}{} }()
	<-done
	return true
}

func camoDecoyAddr(decoyOrigin string) func(sni string) string {
	fallbackHost := ""
	if decoyOrigin != "" {
		if u, err := url.Parse(decoyOrigin); err == nil {
			fallbackHost = u.Hostname()
		} else {
			fallbackHost = decoyOrigin
		}
	}
	return func(sni string) string {
		host := sni
		if !validSNI(host) {
			host = fallbackHost
		}
		if host == "" {
			return ""
		}
		return net.JoinHostPort(host, "443")
	}
}

type camouflageListener struct {
	net.Listener
	ready      chan net.Conn
	closed     chan struct{}
	closeOnce  sync.Once
	keysFn     func() [][]byte
	bySelector func(random, keyShare []byte) (string, []byte, bool)
	decoyAddr  func(sni string) string

	driftMu   sync.Mutex
	driftLast time.Time
}

func newCamouflageListener(inner net.Listener, keysFn func() [][]byte, bySelector func(random, keyShare []byte) (string, []byte, bool), decoyAddr func(string) string) *camouflageListener {
	l := &camouflageListener{
		Listener:   inner,
		ready:      make(chan net.Conn),
		closed:     make(chan struct{}),
		keysFn:     keysFn,
		bySelector: bySelector,
		decoyAddr:  decoyAddr,
	}
	go l.acceptLoop()
	return l
}

func (l *camouflageListener) acceptLoop() {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			l.closeOnce.Do(func() { close(l.closed) })
			return
		}
		go l.handle(conn)
	}
}

var decoyIPRate struct {
	mu        sync.Mutex
	seen      map[string]time.Time
	count     map[string]int
	lastClean time.Time
}

func init() {
	decoyIPRate.seen = make(map[string]time.Time)
	decoyIPRate.count = make(map[string]int)
	decoyIPRate.lastClean = time.Now()
}

const (
	decoyRateWindow     = 10 * time.Second
	decoyRateMax        = 20
	markerDriftInterval = time.Minute
)

func (l *camouflageListener) driftProbeDue() bool {
	l.driftMu.Lock()
	defer l.driftMu.Unlock()
	if time.Since(l.driftLast) < markerDriftInterval {
		return false
	}
	l.driftLast = time.Now()
	return true
}

func decoyIPRateAllow(remote string) bool {
	ip := remote
	if h, _, err := net.SplitHostPort(remote); err == nil {
		ip = h
	}

	decoyIPRate.mu.Lock()
	defer decoyIPRate.mu.Unlock()

	now := time.Now()
	if now.Sub(decoyIPRate.lastClean) > time.Minute {
		for k, t := range decoyIPRate.seen {
			if now.Sub(t) > decoyRateWindow {
				delete(decoyIPRate.seen, k)
				delete(decoyIPRate.count, k)
			}
		}
		decoyIPRate.lastClean = now
	}

	last, ok := decoyIPRate.seen[ip]
	if !ok || now.Sub(last) > decoyRateWindow {
		decoyIPRate.seen[ip] = now
		decoyIPRate.count[ip] = 1
		return true
	}
	decoyIPRate.count[ip]++
	return decoyIPRate.count[ip] <= decoyRateMax
}

func (l *camouflageListener) handle(conn net.Conn) {
	remote := conn.RemoteAddr().String()
	defer func() {
		if r := recover(); r != nil {
			traceLog.Errorw("camo_handle_panic", "remote", remote, "err", fmt.Sprint(r), "stack", string(debug.Stack()))
			conn.Close()
		}
	}()
	ph, err := peekClientHello(conn)

	if err == nil && l.bySelector != nil {
		if userID, psk, ok := l.bySelector(ph.random, ph.keyShare); ok {
			traceLog.Infow("camo_authenticated", "remote", remote, "sni", ph.sni, "via", "selector", "user", userID)
			l.pass(conn, ph, userID, psk)
			return
		}
	}

	var keys [][]byte
	if err == nil {
		keys = l.keysFn()
		if camo.MarkerMatches(keys, ph.random, ph.keyShare) {
			traceLog.Infow("camo_authenticated", "remote", remote, "sni", ph.sni, "via", "scan")
			l.pass(conn, ph, "", nil)
			return
		}
	}
	if len(ph.raw) == 0 {
		traceLog.Infow("camo_no_hello", "remote", remote, "err", err)
		conn.Close()
		return
	}
	if errors.Is(err, errHelloIncomplete) && ph.raw[0] == 0x16 {
		traceLog.Infow("camo_partial_hello", "remote", remote, "err", err)
		conn.Close()
		return
	}
	if err == nil && l.driftProbeDue() {
		if keys == nil {
			keys = l.keysFn()
		}
		if drift, found := camo.MarkerDrift(keys, ph.random, ph.keyShare); found {
			traceLog.Warnw("camo_marker_drift_suspected", "remote", remote, "sni", ph.sni,
				"drift_windows", drift, "drift_seconds", drift*camoWindowSeconds)
		}
	}
	if !decoyIPRateAllow(remote) {
		traceLog.Infow("camo_relay_decoy_throttled", "remote", remote, "sni", ph.sni)
		conn.Close()
		return
	}

	if err == nil && validSNI(ph.sni) {
		fingerprint.CollectFromHello(ph.raw)
	}

	target := l.decoyAddr(ph.sni)
	traceLog.Infow("camo_relay_decoy", "remote", remote, "sni", ph.sni, "hello_err", err,
		"camo_keys", len(keys), "has_keyshare", len(ph.keyShare) > 0, "target", target)
	if relayToOrigin(conn, ph.raw, target) {
		return
	}
	// Nowhere to relay — no decoy origin configured, no usable SNI, or it would
	// not answer. Dropping the connection here is what a tunnel does; a web
	// server presents its certificate and serves something. So the handshake
	// goes on as usual and the decoy pages answer it.
	traceLog.Infow("camo_serve_local_decoy", "remote", remote, "sni", ph.sni, "target", target)
	l.pass(conn, ph, "", nil)
}

func (l *camouflageListener) pass(conn net.Conn, ph *peekedHello, userID string, psk []byte) {
	pc := &prefixConn{Conn: conn, prefix: ph.raw, knownUser: userID, knownPSK: psk}
	select {
	case l.ready <- pc:
	case <-l.closed:
		conn.Close()
	}
}

func (l *camouflageListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.ready:
		return conn, nil
	case <-l.closed:
		return nil, fmt.Errorf("whispera: camouflage listener closed")
	}
}

func (l *camouflageListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return l.Listener.Close()
}

func camoKeysFunc(cfg *ServerConfig) func() [][]byte {
	return func() [][]byte { return cfg.selectors.camoKeys(cfg) }
}
