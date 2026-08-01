package protocol

import (
	"context"
	"errors"
	"fmt"
	"github.com/nekoskin/whispera/core/protocol/fingerprint"
	"io"
	"net"
	"net/url"
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
	camoWindowTol     = authWindowTolerance
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

func peekClientHello(conn net.Conn) (*peekedHello, error) {
	defer conn.SetReadDeadline(time.Time{})

	var raw []byte
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
		payload := make([]byte, recLen)
		if _, err := readFullIdle(conn, payload, camoPeekTimeout); err != nil {
			return &peekedHello{raw: raw}, fmt.Errorf("%w: %v", errHelloIncomplete, err)
		}
		raw = append(raw, payload...)
		hs = append(hs, payload...)

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
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if c.off < len(c.prefix) {
		n := copy(b, c.prefix[c.off:])
		c.off += n
		return n, nil
	}
	return c.Conn.Read(b)
}

func relayToOrigin(conn net.Conn, raw []byte, addr string) {
	defer conn.Close()
	if addr == "" {
		return
	}
	dialCtx, cancel := context.WithTimeout(context.Background(), camoDialTimeout)
	defer cancel()
	upstream, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return
	}
	defer upstream.Close()

	if len(raw) > 0 {
		if _, err := upstream.Write(raw); err != nil {
			return
		}
	}

	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, upstream); done <- struct{}{} }()
	<-done
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
	ready     chan net.Conn
	closed    chan struct{}
	closeOnce sync.Once
	keysFn    func() [][]byte
	decoyAddr func(sni string) string
}

func newCamouflageListener(inner net.Listener, keysFn func() [][]byte, decoyAddr func(string) string) *camouflageListener {
	l := &camouflageListener{
		Listener:  inner,
		ready:     make(chan net.Conn),
		closed:    make(chan struct{}),
		keysFn:    keysFn,
		decoyAddr: decoyAddr,
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
	decoyRateWindow = 10 * time.Second
	decoyRateMax    = 20
)

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
	keys := l.keysFn()
	ph, err := peekClientHello(conn)
	if err == nil && camo.MarkerMatches(keys, ph.random, ph.keyShare) {
		traceLog.Infow("camo_authenticated", "remote", remote, "sni", ph.sni)
		pc := &prefixConn{Conn: conn, prefix: ph.raw}
		select {
		case l.ready <- pc:
		case <-l.closed:
			conn.Close()
		}
		return
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
	if err == nil {
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
	relayToOrigin(conn, ph.raw, target)
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
	return func() [][]byte {
		keys := make([][]byte, 0, 4)
		if len(cfg.SharedSecret) == 32 {
			keys = append(keys, camo.DeriveKey(cfg.SharedSecret))
		}
		if cfg.GetUsers != nil {
			for _, u := range cfg.GetUsers() {
				if len(u.PSK) == 32 {
					keys = append(keys, camo.DeriveKey(u.PSK))
				}
			}
		}
		return keys
	}
}
