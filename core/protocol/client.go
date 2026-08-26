package protocol

import (
	"bytes"
	"context"
	"crypto/ecdh"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nekoskin/whispera/core/protocol/fingerprint"
	"io"
	"math"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nekoskin/whispera/core/protocol/camo"
	quicpkg "github.com/nekoskin/whispera/core/protocol/quic"

	quicgo "github.com/quic-go/quic-go"
	http3 "github.com/quic-go/quic-go/http3"
	utls "github.com/refraction-networking/utls"
)

const dialTimeout = 10 * time.Second

const handshakeTimeout = 3 * time.Second

type helloSplitConn struct {
	net.Conn
	splitAt int
	split   bool
}

func (c *helloSplitConn) Write(b []byte) (int, error) {
	if c.split || c.splitAt <= 0 || c.splitAt >= len(b) {
		c.split = true
		return c.Conn.Write(b)
	}
	c.split = true
	n1, err := c.Conn.Write(b[:c.splitAt])
	if err != nil {
		return n1, err
	}
	n2, err := c.Conn.Write(b[c.splitAt:])
	return n1 + n2, err
}

const liveResetWindow = 8 * time.Second

type livenessConn struct {
	net.Conn
	onReset func()
	onOK    func()

	mu            sync.Mutex
	establishedAt time.Time
	established   bool
	closedByUs    bool
	fired         bool
}

func (c *livenessConn) NetConn() net.Conn { return c.Conn }

func (c *livenessConn) Note(err error) { c.note(err) }

func (c *livenessConn) markEstablished() {
	c.mu.Lock()
	c.established = true
	c.establishedAt = time.Now()
	c.mu.Unlock()
}

func (c *livenessConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil {
		c.note(err)
	}
	return n, err
}

func (c *livenessConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if err != nil {
		c.note(err)
	}
	return n, err
}

func (c *livenessConn) Close() error {
	c.mu.Lock()
	report := c.established && !c.fired && !c.closedByUs
	c.closedByUs = true
	cb := c.onOK
	c.mu.Unlock()
	if report && cb != nil {
		cb()
	}
	return c.Conn.Close()
}

func (c *livenessConn) note(err error) {
	c.mu.Lock()
	if c.fired || !c.established || c.closedByUs || c.onReset == nil {
		c.mu.Unlock()
		return
	}
	if time.Since(c.establishedAt) > liveResetWindow || !isCensorReset(err) {
		c.mu.Unlock()
		return
	}
	c.fired = true
	cb := c.onReset
	c.mu.Unlock()
	cb()
}

func isCensorReset(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "reset") && !strings.Contains(s, "abort")
}

type HandshakeResult int

const (
	HandshakeOK HandshakeResult = iota
	HandshakeResetFast
	HandshakeIncomplete
	HandshakeRejected
	HandshakeError
)

const handshakeResetBlockThreshold = 15 * time.Millisecond

func classifyHandshake(err error, latency time.Duration) HandshakeResult {
	if err == nil {
		return HandshakeOK
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "reset"):
		if latency < handshakeResetBlockThreshold {
			return HandshakeResetFast
		}
		return HandshakeError
	case strings.Contains(s, "decoding message"), strings.Contains(s, "bad certificate"),
		strings.Contains(s, "handshake failure"), strings.Contains(s, "alert"):
		return HandshakeRejected
	case strings.Contains(s, "deadline exceeded"), strings.Contains(s, "timeout"):
		return HandshakeIncomplete
	default:
		return HandshakeError
	}
}

func (r HandshakeResult) Reward() float64 {
	switch r {
	case HandshakeOK:
		return 1.0
	case HandshakeResetFast:
		return -1.0
	case HandshakeRejected:
		return -0.9
	case HandshakeIncomplete:
		return -0.7
	default:
		return -0.3
	}
}

var splitOffsets = []int{0, 8, 24, 64}

type HandshakeStrategy struct {
	mu       sync.Mutex
	sum      map[string][]float64
	cnt      map[string][]int64
	survEWMA float64
	surv     map[string]float64
	seen     map[string]int64
	current  map[string]int
}

func NewHandshakeStrategy() *HandshakeStrategy {
	h := &HandshakeStrategy{
		sum:     make(map[string][]float64),
		cnt:     make(map[string][]int64),
		surv:    make(map[string]float64),
		seen:    make(map[string]int64),
		current: make(map[string]int),
	}
	return h
}

// survSwitchThreshold is how low the survival signal of the arm in use has to
// fall before the controller abandons it. Above it the arm is held: switching a
// tactic that still works only makes the client louder.
const survSwitchThreshold = 0.3

// exploreEpsilon is how often a real dial tries a not-current arm instead of the
// held one, to keep the signal fed across the whole repertoire without a
// separate prober that would put bare handshakes on the wire. A dial that
// explores a worse arm just reconnects — per-flow retries — so the cost is a
// stray reconnect, not a broken session. A var, not a const, so tests can pin it
// to zero and get deterministic hold/switch behavior.
var exploreEpsilon = 0.15

// Select returns the arm (a tactic index into a repertoire of the given size)
// to use for this context. It holds the current arm while its survival signal
// is healthy and switches to the best arm on record only once survival drops —
// adapt when found, not on every dial — but occasionally explores a less-tried
// arm so every tactic keeps getting measured on real traffic.
func (h *HandshakeStrategy) Select(ctx string, arms int) int {
	if arms <= 0 {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	cur, ok := h.current[ctx]
	if !ok || cur < 0 || cur >= arms {
		cur = h.bestArm(ctx, arms)
		h.current[ctx] = cur
		return cur
	}
	if exploreEpsilon > 0 && arms > 1 && mrand.Float64() < exploreEpsilon {
		return h.leastTried(ctx, arms)
	}
	if h.seen[ctx] >= int64(arms) && h.surv[ctx] < survSwitchThreshold {
		if next := h.bestArm(ctx, arms); next != cur {
			traceLog.Infow("arm_switch", "ctx", ctx, "from", cur, "to", next, "survival", h.surv[ctx])
			h.current[ctx] = next
			h.surv[ctx] = survSwitchThreshold
			cur = next
		}
	}
	return cur
}

// leastTried is the arm with the fewest observations, so exploration spends its
// budget where the signal is thinnest.
func (h *HandshakeStrategy) leastTried(ctx string, arms int) int {
	cnt := h.cnt[ctx]
	best, fewest := 0, int64(math.MaxInt64)
	for i := 0; i < arms; i++ {
		var c int64
		if i < len(cnt) {
			c = cnt[i]
		}
		if c < fewest {
			best, fewest = i, c
		}
	}
	return best
}

// bestArm prefers an unexplored arm, then the one with the highest mean reward.
func (h *HandshakeStrategy) bestArm(ctx string, arms int) int {
	sum, cnt := h.sum[ctx], h.cnt[ctx]
	best, bestScore := 0, math.Inf(-1)
	for i := 0; i < arms; i++ {
		score := math.Inf(1)
		if i < len(cnt) && cnt[i] > 0 {
			score = sum[i] / float64(cnt[i])
		}
		if score > bestScore {
			best, bestScore = i, score
		}
	}
	return best
}

func (h *HandshakeStrategy) Record(ctx string, r HandshakeResult) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.seen[ctx] == 0 {
		h.surv[ctx] = 0.5
	}
	surv := 0.0
	if r == HandshakeOK {
		surv = 1.0
	}
	h.surv[ctx] += 0.05 * (surv - h.surv[ctx])
	h.seen[ctx]++
	h.survEWMA += 0.05 * (surv - h.survEWMA)
	traceLog.Infow("handshake_signal",
		"ctx", ctx, "result", int(r), "survival", h.surv[ctx], "seen", h.seen[ctx])
}

type signalSnapshot struct {
	Surv     map[string]float64 `json:"surv"`
	Seen     map[string]int64   `json:"seen"`
	SurvEWMA float64            `json:"surv_ewma"`
}

func (h *HandshakeStrategy) Save(path string) error {
	h.mu.Lock()
	data, err := json.Marshal(signalSnapshot{Surv: h.surv, Seen: h.seen, SurvEWMA: h.survEWMA})
	h.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (h *HandshakeStrategy) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var snap signalSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	h.mu.Lock()
	if snap.Surv != nil {
		h.surv = snap.Surv
	}
	if snap.Seen != nil {
		h.seen = snap.Seen
	}
	h.survEWMA = snap.SurvEWMA
	h.mu.Unlock()
	return nil
}

func (h *HandshakeStrategy) ensure(ctx string, arms int) {
	if len(h.sum[ctx]) < arms {
		s := make([]float64, arms)
		copy(s, h.sum[ctx])
		h.sum[ctx] = s
		c := make([]int64, arms)
		copy(c, h.cnt[ctx])
		h.cnt[ctx] = c
	}
}

func armMean(sum float64, cnt int64) float64 {
	if cnt == 0 {
		return 0
	}
	return sum / float64(cnt)
}

func (h *HandshakeStrategy) SelectSplit(ctx string) (offset, arm int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ensure(ctx, len(splitOffsets))
	sum, cnt := h.sum[ctx], h.cnt[ctx]

	var total int64
	for i, c := range cnt {
		if c == 0 {
			return splitOffsets[i], i
		}
		total += c
	}

	lnTotal := math.Log(float64(total))
	best := math.Inf(-1)
	for i := range splitOffsets {
		norm := (armMean(sum[i], cnt[i]) + 1) / 2
		score := norm + math.Sqrt(2*lnTotal/float64(cnt[i]))
		if score > best {
			best, arm = score, i
		}
	}
	return splitOffsets[arm], arm
}

func (h *HandshakeStrategy) Observe(ctx string, arm int, r HandshakeResult) {
	if arm < 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ensure(ctx, arm+1)
	reward := r.Reward()
	h.sum[ctx][arm] += reward
	h.cnt[ctx][arm]++
	surv := 0.0
	if r == HandshakeOK {
		surv = 1.0
	}
	h.survEWMA += 0.05 * (surv - h.survEWMA)
	traceLog.Infow("handshake_control_observe",
		"ctx", ctx, "arm", arm,
		"result", int(r), "reward", reward, "survival_ewma", h.survEWMA)
}

func Client(ctx context.Context, cfg *ClientConfig) (net.Conn, error) {
	sessionID := make([]byte, 16)
	if _, err := crand.Read(sessionID); err != nil {
		return nil, fmt.Errorf("whispera: session id: %w", err)
	}
	anchor := time.Now().UTC().Truncate(time.Second)

	keys := DeriveKeys(cfg.SharedSecret)
	token := AuthToken(keys.Auth, anchor.Unix()/authWindowSeconds, sessionID)

	sni := sessionSNI(cfg)
	var helloID utls.ClientHelloID
	var helloRaw []byte
	if cfg.HelloID.Client != "" {
		helloID, helloRaw = cfg.HelloID, cfg.HelloRaw
	} else {
		helloID, helloRaw, _ = fingerprint.Session()
	}

	camoKey := camo.DeriveKey(cfg.SharedSecret)

	d := &clientDialer{
		cfg:      cfg,
		sni:      sni,
		camoKey:  camoKey,
		helloID:  helloID,
		helloRaw: helloRaw,
	}

	return dialPerflow(ctx, d, sessionID, token)
}

type clientDialer struct {
	cfg      *ClientConfig
	sni      string
	camoKey  []byte
	helloID  utls.ClientHelloID
	helloRaw []byte

	mu     sync.Mutex
	dialed []net.Conn
	live   *livenessConn
}

func (d *clientDialer) markEstablished() {
	d.mu.Lock()
	live := d.live
	d.mu.Unlock()
	if live != nil {
		live.markEstablished()
	}
}

func (d *clientDialer) dialRaw(ctx context.Context, network, addr string) (net.Conn, error) {
	var rawConn net.Conn
	var err error
	if d.cfg.TCPDialer != nil {
		rawConn, err = d.cfg.TCPDialer(ctx, network, addr)
	} else {
		dl := &net.Dialer{Timeout: dialTimeout}
		rawConn, err = dl.DialContext(ctx, network, addr)
	}
	if err != nil {
		return nil, err
	}
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(time.Duration(30+mrand.Intn(61)) * time.Second)
		tcpConn.SetNoDelay(true)
	}
	lc := &livenessConn{Conn: rawConn, onReset: d.cfg.OnLiveReset, onOK: d.cfg.OnLiveOK}
	d.mu.Lock()
	d.live = lc
	d.mu.Unlock()
	rawConn = lc
	if d.cfg.HelloSplitOffset > 0 {
		rawConn = &helloSplitConn{Conn: rawConn, splitAt: d.cfg.HelloSplitOffset}
	}
	return rawConn, nil
}

func (d *clientDialer) selectorFor(uConn *utls.UConn, keyShare []byte) ([camo.SelectorSize]byte, bool) {
	var none [camo.SelectorSize]byte
	if d.cfg.ServerSelPub == "" || len(d.cfg.SharedSecret) != 32 {
		return none, false
	}
	rawPub, err := base64.StdEncoding.DecodeString(d.cfg.ServerSelPub)
	if err != nil || len(rawPub) != 32 {
		return none, false
	}
	serverPub, err := ecdh.X25519().NewPublicKey(rawPub)
	if err != nil {
		return none, false
	}
	ks := uConn.HandshakeState.State13.KeyShareKeys
	if ks == nil {
		return none, false
	}
	for _, cand := range []*ecdh.PrivateKey{ks.Ecdhe, ks.MlkemEcdhe} {
		if cand == nil || !bytes.Equal(cand.PublicKey().Bytes(), keyShare) {
			continue
		}
		sel, err := camo.BuildSelector(d.cfg.SharedSecret, cand, serverPub)
		if err != nil {
			return none, false
		}
		return sel, true
	}
	return none, false
}

func (d *clientDialer) tlsHandshake(ctx context.Context, rawConn net.Conn, useSpec bool) (*utls.UConn, error) {
	uCfg := &utls.Config{
		ServerName:                         d.sni,
		InsecureSkipVerify:                 true,
		PreferSkipResumptionOnNilExtension: true,
	}
	if d.cfg.ServerCertPin != "" || d.cfg.ServerIDPub != "" {
		uCfg.VerifyPeerCertificate = certVerifier(d.cfg.ServerCertPin, d.cfg.ServerIDPub, d.sni, d.cfg.OnServerSelPub)
	}
	if d.camoKey == nil {
		if sc, ok := d.cfg.SessionCache.(utls.ClientSessionCache); ok {
			uCfg.ClientSessionCache = sc
		}
	}
	var spec *utls.ClientHelloSpec
	if useSpec && len(d.helloRaw) > 0 {
		s, err := fingerprint.SpecFromRaw(d.helloRaw)
		if err != nil {
			return nil, fmt.Errorf("whispera: fingerprint: %w", err)
		}
		hasSNI := false
		for _, ext := range s.Extensions {
			if sni, ok := ext.(*utls.SNIExtension); ok {
				sni.ServerName = d.sni
				hasSNI = true
			}
		}
		if !hasSNI && d.sni != "" {
			s.Extensions = append([]utls.TLSExtension{&utls.SNIExtension{ServerName: d.sni}}, s.Extensions...)
		}
		spec = s
	} else {
		s, err := utls.UTLSIdToSpec(d.helloID)
		if err != nil {
			return nil, fmt.Errorf("whispera: fingerprint: %w", err)
		}
		spec = &s
	}
	if fingerprint.DropPQEnabled() {
		fingerprint.DropPQKeyShares(spec)
	}
	uConn := utls.UClient(rawConn, uCfg, utls.HelloCustom)
	if err := uConn.ApplyPreset(spec); err != nil {
		return nil, fmt.Errorf("whispera: apply fingerprint: %w", err)
	}
	if err := uConn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("whispera: build hello: %w", err)
	}
	if d.camoKey != nil {
		if hello := uConn.HandshakeState.Hello; hello != nil && len(hello.Random) == 32 {
			if keyShare := camo.ExtractX25519KeyShare(hello.KeyShares); len(keyShare) > 0 {
				if sel, ok := d.selectorFor(uConn, keyShare); ok {
					camo.WriteRandom(hello.Random, sel, d.camoKey, time.Now().Unix()/camo.WindowSeconds, keyShare)
				} else {
					marker := camo.BuildMarker(d.camoKey, keyShare)
					copy(hello.Random, marker[:])
				}
			}
		}
	}
	start := time.Now()
	hsErr := uConn.HandshakeContext(ctx)
	if d.cfg.OnHandshake != nil {
		latency := time.Since(start)
		d.cfg.OnHandshake(classifyHandshake(hsErr, latency), latency)
	}
	if hsErr != nil {
		return nil, fmt.Errorf("whispera: utls handshake: %w", hsErr)
	}
	return uConn, nil
}

func (d *clientDialer) handshakeWithin(ctx context.Context, rawConn net.Conn, useSpec bool) (*utls.UConn, error) {
	hsCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	return d.tlsHandshake(hsCtx, rawConn, useSpec)
}

func helloRetryWorthwhile(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false
	}
	return !errors.Is(err, os.ErrDeadlineExceeded)
}

func (d *clientDialer) dialTLS(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
	start := time.Now()
	rawConn, err := d.dialRaw(ctx, network, addr)
	if err != nil {
		if d.cfg.OnHandshake != nil {
			latency := time.Since(start)
			d.cfg.OnHandshake(classifyHandshake(err, latency), latency)
		}
		return nil, err
	}
	uConn, err := d.handshakeWithin(ctx, rawConn, true)
	if err != nil && len(d.helloRaw) > 0 && helloRetryWorthwhile(ctx, err) {
		rawConn.Close()
		rawConn, err = d.dialRaw(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		uConn, err = d.handshakeWithin(ctx, rawConn, false)
	}
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	d.mu.Lock()
	d.dialed = append(d.dialed, uConn)
	d.mu.Unlock()
	return uConn, nil
}

func dialPerflow(ctx context.Context, d *clientDialer, sessionID []byte, token string) (net.Conn, error) {
	uConn, err := d.dialTLS(ctx, "tcp", d.cfg.ServerAddr, nil)
	if err != nil {
		return nil, err
	}
	pre := make([]byte, 0, 1+len(sessionID)+2+len(token))
	pre = append(pre, perflowMagic)
	pre = append(pre, sessionID...)
	pre = binary.BigEndian.AppendUint16(pre, uint16(len(token)))
	pre = append(pre, token...)
	if _, err := uConn.Write(pre); err != nil {
		uConn.Close()
		return nil, err
	}
	d.markEstablished()
	logTransportMode("perflow")
	return uConn, nil
}

func DialRTDatagrams(ctx context.Context, cfg *ClientConfig) error {
	if cfg.QUICAddr == "" {
		return fmt.Errorf("whispera: no QUIC address configured")
	}

	sessionID := make([]byte, 16)
	if _, err := crand.Read(sessionID); err != nil {
		return fmt.Errorf("whispera: session id: %w", err)
	}
	anchor := time.Now().UTC().Truncate(time.Second)
	keys := DeriveKeys(cfg.SharedSecret)
	token := AuthToken(keys.Auth, anchor.Unix()/authWindowSeconds, sessionID)

	sni := sessionSNI(cfg)
	tr := newQUICTransport(cfg, sni)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("https://%s/", cfg.QUICAddr), http.NoBody)
	if err != nil {
		return err
	}
	req.Host = sni
	req.Header.Set(rtDatagramTokenHeader, "Bearer "+token)
	req.Header.Set(rtDatagramSessionHeader, hex.EncodeToString(sessionID))

	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return fmt.Errorf("whispera: rt datagram register: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return fmt.Errorf("whispera: rt datagram register: status %d", resp.StatusCode)
	}

	logTransportMode("rt-datagrams")
	go func() {
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
	}()
	return nil
}

func newQUICTransport(cfg *ClientConfig, sni string) http.RoundTripper {
	tlsCfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	}
	if cfg.ServerCertPin != "" || cfg.ServerIDPub != "" {
		tlsCfg.VerifyPeerCertificate = certVerifier(cfg.ServerCertPin, cfg.ServerIDPub, sni, cfg.OnServerSelPub)
	}
	return &http3.Transport{
		TLSClientConfig:    tlsCfg,
		QUICConfig:         chromeLikeQUICConfig(),
		DisableCompression: true,
		Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, qCfg *quicgo.Config) (*quicgo.Conn, error) {
			udpAddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, err
			}
			pconn, err := net.ListenUDP("udp", nil)
			if err != nil {
				return nil, err
			}
			if camoKey := camo.DeriveKey(cfg.SharedSecret); camoKey != nil {
				if probe, perr := quicpkg.BuildCamoProbe(camoKey, sni); perr == nil {
					_, _ = pconn.WriteToUDP(probe, udpAddr)
				}
			}
			qconn, derr := quicgo.Dial(ctx, pconn, udpAddr, tlsConf, qCfg)
			if derr == nil && cfg.OnQUICConn != nil {
				cfg.OnQUICConn(qconn)
			}
			return qconn, derr
		},
	}
}
