package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

const (
	camoWindowSeconds = authWindowSeconds
	camoWindowTol     = authWindowTolerance
	camoPeekTimeout   = 4 * time.Second
	camoMaxHandshake  = 8192
	camoDialTimeout   = 5 * time.Second
)

// deriveCamoKey derives the steganographic ClientHello-marker key from a
// tunnel PSK. Kept separate from DeriveKeys so a leak of one purpose's key
// doesn't help with the other.
func deriveCamoKey(psk []byte) []byte {
	if len(psk) != 32 {
		return nil
	}
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte("whispera-camo-v1"))
	return mac.Sum(nil)
}

// extractX25519KeyShare pulls out the connection's own ephemeral ECDHE
// public key. It is unique per TLS connection by construction (freshly
// generated for every handshake), which is what the marker is bound to
// instead of a replay cache: a captured ClientHello can be copied onto a
// new TCP connection verbatim, but the attacker still lacks the matching
// ECDHE private key and can never complete a working tunnel with it, so
// there is nothing to gain by replaying it.
func extractX25519KeyShare(shares []utls.KeyShare) []byte {
	for _, ks := range shares {
		if ks.Group == utls.X25519 {
			return ks.Data
		}
	}
	return nil
}

func camoMarkerForWindow(key []byte, window int64, keyShare []byte) [32]byte {
	var out [32]byte
	mac := hmac.New(sha256.New, key)
	var wb [8]byte
	binary.BigEndian.PutUint64(wb[:], uint64(window))
	mac.Write(wb[:])
	mac.Write(keyShare)
	copy(out[:], mac.Sum(nil))
	return out
}

// buildCamoMarker produces 32 bytes that are placed verbatim into the
// ClientHello's Random field. To an observer it is indistinguishable from a
// genuine random nonce; to a server holding the same PSK it authenticates
// the connection without any extra round trip. Binding it to this
// connection's own key_share means two connections opened in the same time
// window (e.g. a client retry) never collide, and a copied ClientHello
// can't be reused to authenticate a different connection.
func buildCamoMarker(key []byte, keyShare []byte) [32]byte {
	w := time.Now().Unix() / camoWindowSeconds
	return camoMarkerForWindow(key, w, keyShare)
}

func camoMarkerMatches(keys [][]byte, random []byte, keyShare []byte) bool {
	if len(random) != 32 || len(keys) == 0 || len(keyShare) == 0 {
		return false
	}
	w := time.Now().Unix() / camoWindowSeconds
	for _, key := range keys {
		if len(key) == 0 {
			continue
		}
		for cand := w - camoWindowTol; cand <= w+camoWindowTol; cand++ {
			marker := camoMarkerForWindow(key, cand, keyShare)
			if hmac.Equal(marker[:], random) {
				return true
			}
		}
	}
	return false
}

// peekedHello holds the verbatim wire bytes consumed while sniffing a
// ClientHello, plus the parsed fields we need to make a routing decision.
type peekedHello struct {
	raw      []byte
	random   []byte
	sni      string
	keyShare []byte
}

// peekClientHello reassembles a (possibly record-fragmented) TLS ClientHello
// off conn without consuming more than the handshake message itself, so the
// exact bytes can be replayed either into our own TLS stack or onward to a
// real origin server.
func peekClientHello(conn net.Conn) (*peekedHello, error) {
	_ = conn.SetReadDeadline(time.Now().Add(camoPeekTimeout))
	defer conn.SetReadDeadline(time.Time{})

	var raw []byte
	var hs []byte

	for {
		var hdr [5]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return &peekedHello{raw: raw}, err
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
		if _, err := io.ReadFull(conn, payload); err != nil {
			return &peekedHello{raw: raw}, err
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
			keyShare: extractX25519KeyShare(msg.KeyShares),
		}, nil
	}
}

// prefixConn replays previously-consumed bytes before resuming reads from
// the underlying connection, so a peeked ClientHello can be handed to the
// real TLS stack as if nothing had been read yet.
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

// relayToOrigin forwards a connection verbatim (starting with the bytes
// already consumed while peeking) to a real upstream server, byte for byte,
// without ever terminating TLS itself. Anyone without the PSK marker, be it
// a browser, a scanner, or active-probing DPI, sees a completely genuine
// connection to the destination they asked for.
func relayToOrigin(conn net.Conn, raw []byte, addr string) {
	defer conn.Close()
	if addr == "" {
		return
	}
	upstream, err := net.DialTimeout("tcp", addr, camoDialTimeout)
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

// camoDecoyAddr resolves the real address to forward unauthenticated
// connections to: the SNI the client actually asked for when valid,
// falling back to the configured decoy origin otherwise.
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

// camouflageListener sits between the raw TCP accept loop and the TLS
// listener. Connections that open with a PSK-marked ClientHello are handed
// through to our TLS stack unchanged; everything else is transparently
// relayed to a real origin server and never reaches our TLS stack at all.
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
			close(l.ready)
			return
		}
		go l.handle(conn)
	}
}

func (l *camouflageListener) handle(conn net.Conn) {
	remote := conn.RemoteAddr().String()
	ph, err := peekClientHello(conn)
	if err == nil && camoMarkerMatches(l.keysFn(), ph.random, ph.keyShare) {
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
	target := l.decoyAddr(ph.sni)
	traceLog.Infow("camo_relay_decoy", "remote", remote, "sni", ph.sni, "hello_err", err, "target", target)
	relayToOrigin(conn, ph.raw, target)
}

func (l *camouflageListener) Accept() (net.Conn, error) {
	conn, ok := <-l.ready
	if !ok {
		return nil, fmt.Errorf("whispera: camouflage listener closed")
	}
	return conn, nil
}

func (l *camouflageListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return l.Listener.Close()
}

// camoKeysFunc builds the per-connection PSK lookup closure for a server,
// covering both the single shared-secret deployment and multi-user ones.
func camoKeysFunc(cfg *ServerConfig) func() [][]byte {
	return func() [][]byte {
		keys := make([][]byte, 0, 4)
		if len(cfg.SharedSecret) == 32 {
			keys = append(keys, deriveCamoKey(cfg.SharedSecret))
		}
		if cfg.GetUsers != nil {
			for _, u := range cfg.GetUsers() {
				if len(u.PSK) == 32 {
					keys = append(keys, deriveCamoKey(u.PSK))
				}
			}
		}
		return keys
	}
}
