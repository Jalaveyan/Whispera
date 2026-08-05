package protocol

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/nekoskin/whispera/core/protocol/fingerprint"
	"hash/fnv"
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

	"github.com/nekoskin/whispera/neural"

	quicgo "github.com/quic-go/quic-go"
	http3 "github.com/quic-go/quic-go/http3"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"

	"github.com/nekoskin/whispera/common/buf"
)

const dialTimeout = 10 * time.Second

const helloServerWork = 200 * time.Millisecond

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

const hsFeatureBuckets = 16

type HandshakeStrategy struct {
	mu       sync.Mutex
	sum      map[string][]float64
	cnt      map[string][]int64
	policy   *neural.Policy
	survEWMA float64
}

func NewHandshakeStrategy() *HandshakeStrategy {
	h := &HandshakeStrategy{
		sum: make(map[string][]float64),
		cnt: make(map[string][]int64),
	}
	if handshakePolicyEnabled() {
		h.policy = neural.NewPolicy(hsFeatureBuckets, 16, len(splitOffsets), 0.05, time.Now().UnixNano())
	}
	return h
}

func handshakePolicyEnabled() bool { return os.Getenv("WHISPERA_HS_POLICY") == "1" }

func hsFeatures(ctx string) []float64 {
	x := make([]float64, hsFeatureBuckets)
	f := fnv.New32a()
	_, _ = f.Write([]byte(ctx))
	x[f.Sum32()%hsFeatureBuckets] = 1
	return x
}

func (h *HandshakeStrategy) ensure(ctx string) {
	if h.sum[ctx] == nil {
		h.sum[ctx] = make([]float64, len(splitOffsets))
		h.cnt[ctx] = make([]int64, len(splitOffsets))
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
	h.ensure(ctx)
	if h.policy != nil {
		arm, _ = h.policy.Sample(hsFeatures(ctx))
		return splitOffsets[arm], arm
	}
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
	if arm < 0 || arm >= len(splitOffsets) {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ensure(ctx)
	reward := r.Reward()
	h.sum[ctx][arm] += reward
	h.cnt[ctx][arm]++
	if h.policy != nil {
		h.policy.Update(hsFeatures(ctx), arm, reward)
		surv := 0.0
		if r == HandshakeOK {
			surv = 1.0
		}
		h.survEWMA += 0.05 * (surv - h.survEWMA)
		traceLog.Infow("handshake_policy_observe",
			"ctx", ctx, "arm", arm, "offset", splitOffsets[arm],
			"result", int(r), "reward", reward, "survival_ewma", h.survEWMA)
	}
}

func newH2Transport(dial func(context.Context, string, string, *tls.Config) (net.Conn, error)) *http2.Transport {
	budget := buf.PerConnBudget()
	stub := &http.Transport{
		HTTP2: &http.HTTP2Config{
			MaxReceiveBufferPerStream:     budget,
			MaxReceiveBufferPerConnection: budget,
		},
	}
	h2t, err := http2.ConfigureTransports(stub)
	if err != nil || h2t == nil {
		h2t = &http2.Transport{}
	}
	h2t.ConnPool = nil
	h2t.MaxReadFrameSize = 1 << 20
	h2t.MaxDecoderHeaderTableSize = 65536
	h2t.MaxHeaderListSize = 262144
	h2t.DisableCompression = true
	h2t.DialTLSContext = dial
	return h2t
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
	helloID, helloRaw, _ := fingerprint.Session()

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
	if d.cfg.HelloSplitOffset > 0 {
		rawConn = &helloSplitConn{Conn: rawConn, splitAt: d.cfg.HelloSplitOffset}
	}
	return rawConn, nil
}

func (d *clientDialer) tlsHandshake(ctx context.Context, rawConn net.Conn, useSpec bool) (*utls.UConn, error) {
	uCfg := &utls.Config{
		ServerName:                         d.sni,
		InsecureSkipVerify:                 true,
		PreferSkipResumptionOnNilExtension: true,
	}
	if d.cfg.ServerCertPin != "" || d.cfg.ServerIDPub != "" {
		uCfg.VerifyPeerCertificate = certVerifier(d.cfg.ServerCertPin, d.cfg.ServerIDPub, d.sni)
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
		spec = s
	} else {
		s, err := utls.UTLSIdToSpec(d.helloID)
		if err != nil {
			return nil, fmt.Errorf("whispera: fingerprint: %w", err)
		}
		spec = &s
	}
	fingerprint.DropPQKeyShares(spec)
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
				marker := camo.BuildMarker(d.camoKey, keyShare)
				copy(hello.Random, marker[:])
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

func helloBudget(rtt time.Duration) time.Duration {
	return rtt + helloServerWork
}

func (d *clientDialer) dialRawTimed(ctx context.Context, network, addr string) (net.Conn, time.Duration, error) {
	start := time.Now()
	conn, err := d.dialRaw(ctx, network, addr)
	return conn, time.Since(start), err
}

func (d *clientDialer) handshakeWithin(ctx context.Context, rawConn net.Conn, rtt time.Duration, useSpec bool) (*utls.UConn, error) {
	hsCtx, cancel := context.WithTimeout(ctx, helloBudget(rtt))
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
	rawConn, rtt, err := d.dialRawTimed(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	uConn, err := d.handshakeWithin(ctx, rawConn, rtt, true)
	if err != nil && len(d.helloRaw) > 0 && helloRetryWorthwhile(ctx, err) {
		rawConn.Close()
		rawConn, rtt, err = d.dialRawTimed(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		uConn, err = d.handshakeWithin(ctx, rawConn, rtt, false)
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
		tlsCfg.VerifyPeerCertificate = certVerifier(cfg.ServerCertPin, cfg.ServerIDPub, sni)
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
