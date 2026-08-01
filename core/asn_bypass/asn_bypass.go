package asn_bypass

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

type Strategy int

const (
	StrategyDirect Strategy = iota

	StrategyTLSMasquerade

	StrategyCloudflareBypass

	StrategyGRPC
)

type SNICategory struct {
	Name        string
	Domains     []string
	MinDuration time.Duration
	MaxDuration time.Duration
}

type TimedConn struct {
	net.Conn
	closeTimer *time.Timer
}

type interceptorConn struct {
	net.Conn
	buf      bytes.Buffer
	mu       sync.Mutex
	captured bool
	closed   bool
}

type Config struct {
	Strategy Strategy

	TLSFingerprint string
	TLSMinVersion  uint16
	TLSMaxVersion  uint16

	EnableECH    bool
	ECHConfigURL string

	EnableJA3Randomization bool
	EnableTLSFragmentation bool
	TLSFragmentSize        int
	ConnectionBurstLimit   int
	ConnectionCooldown     time.Duration

	FallbackStrategies []Strategy
	FailoverTimeout    time.Duration
}

type firstWriteFragConn struct {
	net.Conn
	fragSize int
	done     bool
	mu       sync.Mutex
}

type Dialer struct {
	config *Config
	mu     sync.RWMutex

	connCount     int
	lastConnReset time.Time
	countMu       sync.Mutex

	directAttempts int64
	successCount   int64
	failureCount   int64
}

type dialResult struct {
	conn net.Conn
	err  error
}

func (d *Dialer) DialTCP(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.dialDirect(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if d.config.EnableTLSFragmentation {
		fragSize := d.config.TLSFragmentSize
		if fragSize <= 0 {
			fragSize = 40
		}
		return &firstWriteFragConn{Conn: conn, fragSize: fragSize}, nil
	}
	return conn, nil
}

func (c *firstWriteFragConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.done {
		c.mu.Unlock()
		return c.Conn.Write(b)
	}
	c.done = true
	err := writeFragmentedTLSRecord(c.Conn, b, c.fragSize)
	c.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func writeFragmentedTLSRecord(conn net.Conn, data []byte, fragSize int) error {
	if len(data) < 6 || data[0] != 0x16 {
		_, err := conn.Write(data)
		return err
	}
	contentType := data[0]
	majorVer := data[1]
	minorVer := data[2]
	payload := data[5:]

	base := fragSize
	if base < 8 {
		base = 8
	}
	lo, hi := base/2, base+base/2
	if lo < 8 {
		lo = 8
	}

	for len(payload) > 0 {
		chunk := lo + rand.Intn(hi-lo+1)
		if chunk > len(payload) {
			chunk = len(payload)
		}
		record := make([]byte, 5+chunk)
		record[0] = contentType
		record[1] = majorVer
		record[2] = minorVer
		record[3] = byte(chunk >> 8)
		record[4] = byte(chunk)
		copy(record[5:], payload[:chunk])
		payload = payload[chunk:]
		if _, err := conn.Write(record); err != nil {
			return err
		}
		if len(payload) > 0 {
			time.Sleep(time.Duration(rand.Intn(4)+1) * time.Millisecond)
		}
	}
	return nil
}

func DefaultConfig() *Config {
	return &Config{
		Strategy:               StrategyTLSMasquerade,
		TLSFingerprint:         "chrome",
		TLSMinVersion:          tls.VersionTLS13,
		TLSMaxVersion:          tls.VersionTLS13,
		EnableJA3Randomization: true,
		EnableTLSFragmentation: true,
		TLSFragmentSize:        40,
		ConnectionBurstLimit:   5,
		ConnectionCooldown:     2 * time.Second,
		FallbackStrategies:     []Strategy{StrategyCloudflareBypass},
		FailoverTimeout:        30 * time.Second,
	}
}

func NewDialer(cfg *Config) *Dialer {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Dialer{
		config:        cfg,
		lastConnReset: time.Now(),
	}
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if !d.checkBurstLimit() {
		select {
		case <-time.After(d.config.ConnectionCooldown):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	resultCh := make(chan dialResult, len(d.config.FallbackStrategies)+1)
	raceCtx, raceCancel := context.WithTimeout(ctx, d.config.FailoverTimeout)
	defer raceCancel()

	go func() {
		conn, err := d.dialWithStrategy(raceCtx, network, addr, d.config.Strategy)
		select {
		case resultCh <- dialResult{conn, err}:
		case <-raceCtx.Done():
			if conn != nil {
				conn.Close()
			}
		}
	}()

	for _, strategy := range d.config.FallbackStrategies {
		if strategy == d.config.Strategy {
			continue
		}
		go func(s Strategy) {
			conn, err := d.dialWithStrategy(raceCtx, network, addr, s)
			select {
			case resultCh <- dialResult{conn, err}:
			case <-raceCtx.Done():
				if conn != nil {
					conn.Close()
				}
			}
		}(strategy)
	}

	numStrategies := len(d.config.FallbackStrategies) + 1
	var lastErr error
	for i := 0; i < numStrategies; i++ {
		select {
		case res := <-resultCh:
			if res.err == nil && res.conn != nil {
				d.recordSuccess()
				return res.conn, nil
			}
			lastErr = res.err
		case <-raceCtx.Done():
			d.recordFailure()
			return nil, fmt.Errorf("all bypass strategies timed out, last error: %w", lastErr)
		}
	}

	d.recordFailure()
	return nil, fmt.Errorf("all bypass strategies failed, last error: %w", lastErr)
}

var strategyDialers = map[Strategy]func(d *Dialer, ctx context.Context, network, addr string) (net.Conn, error){
	StrategyDirect: func(d *Dialer, ctx context.Context, network, addr string) (net.Conn, error) {
		return d.dialDirect(ctx, network, addr)
	},
	StrategyTLSMasquerade: func(d *Dialer, ctx context.Context, network, addr string) (net.Conn, error) {
		return d.dialTLSMasquerade(ctx, network, addr)
	},
	StrategyCloudflareBypass: func(d *Dialer, ctx context.Context, _, addr string) (net.Conn, error) {
		return d.dialCloudflareBypass(ctx, addr)
	},
	StrategyGRPC: func(d *Dialer, ctx context.Context, _, addr string) (net.Conn, error) { return d.dialGRPC(ctx, addr) },
}

func (d *Dialer) dialWithStrategy(ctx context.Context, network, addr string, strategy Strategy) (net.Conn, error) {
	if fn, ok := strategyDialers[strategy]; ok {
		return fn(d, ctx, network, addr)
	}
	return d.dialDirect(ctx, network, addr)
}

func (d *Dialer) dialDirect(ctx context.Context, _, addr string) (net.Conn, error) {
	conn, err := (&net.Dialer{
		KeepAlive: 30 * time.Second,
	}).DialContext(ctx, "tcp4", addr)

	if err != nil {
		return nil, err
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(15 * time.Second)
	}

	return conn, nil
}

func (d *Dialer) dialTLSMasquerade(ctx context.Context, network, addr string) (net.Conn, error) {
	tcpConn, err := d.dialDirect(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}

	fingerprint := d.getUTLSFingerprint()

	sniToUse, _, err := net.SplitHostPort(addr)
	if err != nil {
		sniToUse = addr
	}

	tlsConfig := &utls.Config{
		ServerName:                         sniToUse,
		InsecureSkipVerify:                 false,
		MinVersion:                         d.config.TLSMinVersion,
		MaxVersion:                         d.config.TLSMaxVersion,
		PreferSkipResumptionOnNilExtension: true,
	}

	interceptor := newInterceptorConn()
	uconn := utls.UClient(interceptor, tlsConfig, *fingerprint)

	if d.config.EnableJA3Randomization {
		if err := d.randomizeJA3(uconn); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("ja3 randomization failed: %w", err)
		}
	}

	go func() {
		defer func() { _ = recover() }()
		_ = uconn.Handshake()
	}()

	clientHello, err := interceptor.WaitForBytes(5 * time.Second)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("failed to generate ClientHello: %w", err)
	}

	if d.config.EnableTLSFragmentation && len(clientHello) > 5 {
		if err := d.writeFragmentedTLS(tcpConn, clientHello); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("write fragmented client hello failed: %w", err)
		}
	} else if _, err := tcpConn.Write(clientHello); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("write client hello failed: %w", err)
	}

	tcpConn.SetReadDeadline(time.Time{})

	return tcpConn, nil
}

func (d *Dialer) dialCloudflareBypass(ctx context.Context, addr string) (net.Conn, error) {
	tcpConn, err := d.dialDirect(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	host, _, _ := net.SplitHostPort(addr)

	uconn := utls.UClient(tcpConn, &utls.Config{
		ServerName:                         host,
		NextProtos:                         []string{"h2", "http/1.1"},
		MinVersion:                         tls.VersionTLS13,
		MaxVersion:                         tls.VersionTLS13,
		PreferSkipResumptionOnNilExtension: true,
	}, utls.HelloChrome_Auto)

	if err := uconn.BuildHandshakeState(); err == nil {
		spec := uconn.HandshakeState.Hello
		_ = spec
	}

	if err := uconn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("cloudflare bypass handshake failed: %w", err)
	}

	return uconn, nil
}

func (d *Dialer) dialGRPC(ctx context.Context, addr string) (net.Conn, error) {
	tlsConn, err := d.dialTLSMasquerade(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	if _, err := tlsConn.Write(preface); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("http2 preface failed: %w", err)
	}

	return tlsConn, nil
}

func (d *Dialer) getUTLSFingerprint() *utls.ClientHelloID {
	fp := d.config.TLSFingerprint

	fingerprintMap := map[string]*utls.ClientHelloID{
		"chrome":     &utls.HelloChrome_Auto,
		"firefox":    &utls.HelloFirefox_Auto,
		"safari":     &utls.HelloSafari_Auto,
		"ios":        &utls.HelloIOS_Auto,
		"android":    &utls.HelloAndroid_11_OkHttp,
		"vk":         &utls.HelloAndroid_11_OkHttp,
		"max":        &utls.HelloAndroid_11_OkHttp,
		"edge":       &utls.HelloEdge_Auto,
		"360":        &utls.Hello360_Auto,
		"qq":         &utls.HelloQQ_Auto,
		"randomized": &utls.HelloRandomized,
	}

	if id, ok := fingerprintMap[fp]; ok {
		return id
	}
	return &utls.HelloChrome_Auto
}

func (d *Dialer) writeFragmentedTLS(conn net.Conn, data []byte) error {
	fragSize := d.config.TLSFragmentSize
	if fragSize <= 0 || fragSize > 64 {
		fragSize = 40
	}

	if len(data) < 6 || data[0] != 0x16 {
		_, err := conn.Write(data)
		return err
	}

	contentType := data[0]
	majorVer := data[1]
	minorVer := data[2]
	payload := data[5:]

	for len(payload) > 0 {
		chunk := payload
		if len(chunk) > fragSize {
			chunk = payload[:fragSize]
		}
		payload = payload[len(chunk):]

		record := make([]byte, 5+len(chunk))
		record[0] = contentType
		record[1] = majorVer
		record[2] = minorVer
		record[3] = byte(len(chunk) >> 8)
		record[4] = byte(len(chunk))
		copy(record[5:], chunk)

		if _, err := conn.Write(record); err != nil {
			return err
		}

		if len(payload) > 0 {
			jitter := time.Duration(rand.Intn(10)+1) * time.Millisecond
			time.Sleep(jitter)
		}
	}
	return nil
}

func (d *Dialer) randomizeJA3(conn *utls.UConn) error {
	extensions := conn.Extensions
	if len(extensions) <= 2 {
		return conn.BuildHandshakeState()
	}

	var sni utls.TLSExtension
	var psk utls.TLSExtension
	sniIdx := -1
	pskIdx := -1
	shuffleable := make([]utls.TLSExtension, 0, len(extensions))

	for i, ext := range extensions {
		switch ext.(type) {
		case *utls.SNIExtension:
			sni = ext
			sniIdx = i
		case *utls.FakePreSharedKeyExtension, *utls.UtlsPreSharedKeyExtension:
			psk = ext
			pskIdx = i
		default:
			shuffleable = append(shuffleable, ext)
		}
	}

	rand.Shuffle(len(shuffleable), func(i, j int) {
		shuffleable[i], shuffleable[j] = shuffleable[j], shuffleable[i]
	})

	result := make([]utls.TLSExtension, 0, len(extensions))
	if sniIdx >= 0 {
		result = append(result, sni)
	}
	result = append(result, shuffleable...)
	if pskIdx >= 0 {
		result = append(result, psk)
	}
	conn.Extensions = result

	if err := conn.BuildHandshakeState(); err != nil {
		return err
	}

	return nil
}

func (d *Dialer) checkBurstLimit() bool {
	d.countMu.Lock()
	defer d.countMu.Unlock()

	now := time.Now()
	if now.Sub(d.lastConnReset) > d.config.ConnectionCooldown {
		d.connCount = 0
		d.lastConnReset = now
	}

	if d.connCount >= d.config.ConnectionBurstLimit {
		return false
	}

	d.connCount++
	return true
}

func (d *Dialer) recordSuccess() {
	d.mu.Lock()
	d.successCount++
	d.mu.Unlock()
}

func (d *Dialer) recordFailure() {
	d.mu.Lock()
	d.failureCount++
	d.mu.Unlock()
}

func (d *Dialer) Stats() map[string]int64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return map[string]int64{
		"success": d.successCount,
		"failure": d.failureCount,
		"direct":  d.directAttempts,
	}
}

func (d *Dialer) SetStrategy(s Strategy) {
	d.mu.Lock()
	d.config.Strategy = s
	d.mu.Unlock()
}

func (d *Dialer) SetFingerprint(fp string) {
	d.mu.Lock()
	d.config.TLSFingerprint = fp
	d.mu.Unlock()
}

func (d *Dialer) CreateHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: d.DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Timeout: 30 * time.Second,
	}
}

func newInterceptorConn() *interceptorConn {
	return &interceptorConn{}
}

func (ic *interceptorConn) Write(b []byte) (int, error) {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	if ic.closed {
		return 0, io.ErrClosedPipe
	}
	n, err := ic.buf.Write(b)
	ic.captured = true
	return n, err
}

func (ic *interceptorConn) Read(b []byte) (int, error) {
	return 0, io.EOF
}

func (ic *interceptorConn) Close() error {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	ic.closed = true
	return nil
}

func (ic *interceptorConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (ic *interceptorConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (ic *interceptorConn) SetDeadline(t time.Time) error      { return nil }
func (ic *interceptorConn) SetReadDeadline(t time.Time) error  { return nil }
func (ic *interceptorConn) SetWriteDeadline(t time.Time) error { return nil }

func (ic *interceptorConn) WaitForBytes(timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)

	for {
		ic.mu.Lock()
		if ic.buf.Len() > 0 {
			out := make([]byte, ic.buf.Len())
			copy(out, ic.buf.Bytes())
			ic.mu.Unlock()
			return out, nil
		}
		ic.mu.Unlock()

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timeout waiting for ClientHello")
		}

		time.Sleep(10 * time.Millisecond)
	}
}
