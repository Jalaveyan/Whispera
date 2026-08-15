package protocol

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	stdlog "log"
	mrand "math/rand"
	"net"
	"os"
	"sync"
	"time"

	quicgo "github.com/quic-go/quic-go"
	utls "github.com/refraction-networking/utls"

	logger "github.com/nekoskin/whispera/common/log"
)

var loggedTransportModes sync.Map

func logTransportMode(mode string) {
	if _, seen := loggedTransportModes.LoadOrStore(mode, struct{}{}); !seen {
		stdlog.Printf("whispera: transport=%s", mode)
	}
}

type UserEntry struct {
	UserID string
	PSK    []byte
}

var traceLog = logger.Trace()

func NewSessionCache(capacity int) any {
	return utls.NewLRUClientSessionCache(capacity)
}

var sharedSessionCache = NewSessionCache(256)

func SharedSessionCache() any { return sharedSessionCache }

var decoyGraph = [4][]string{
	{"/api/v1/config", "/cdn/app/index.js", "/assets/main.css"},
	{"/static/vendor.js", "/static/app.js", "/assets/theme.css", "/cdn/fonts/roboto.woff2"},
	{"/static/icons/192.png", "/favicon.ico", "/manifest.json", "/robots.txt"},
	{"/api/v1/health", "/api/v1/status"},
}

const (
	rtDatagramTokenHeader   = "X-Client-Data"
	rtDatagramSessionHeader = "X-Request-Id"
)

const perflowMagic byte = 0xE7

const perflowPreambleTimeout = 15 * time.Second

func perflowEnabled() bool { return os.Getenv("WHISPERA_PERFLOW") != "0" }

const SpliceProtoBit byte = 0x80

// FullFrameProtoBit asks the server to keep framing records for the whole
// session instead of stopping after the first few — a stream that loses TLS
// record structure halfway through is trivially spotted. On by default; the
// switch exists because a client newer than its server would break on the bit.
const FullFrameProtoBit byte = 0x40

func FullFrameEnabled() bool { return os.Getenv("WHISPERA_FULL_FRAME") != "0" }

func SpliceEnabled() bool { return perflowEnabled() && os.Getenv("WHISPERA_SPLICE") != "0" }

func StreamMuxEnabled() bool { return os.Getenv("WHISPERA_STREAM_MUX") == "1" }

func NetConnOf(c net.Conn) net.Conn {
	if nc, ok := c.(interface{ NetConn() net.Conn }); ok {
		if raw := nc.NetConn(); raw != nil {
			return raw
		}
	}
	return nil
}

func chromeLikeQUICConfig() *quicgo.Config {
	return &quicgo.Config{
		Versions:                       []quicgo.Version{quicgo.Version1},
		MaxIdleTimeout:                 30 * time.Second,
		HandshakeIdleTimeout:           10 * time.Second,
		InitialStreamReceiveWindow:     6 * 1024 * 1024,
		MaxStreamReceiveWindow:         6 * 1024 * 1024,
		InitialConnectionReceiveWindow: 15 * 1024 * 1024,
		MaxConnectionReceiveWindow:     15 * 1024 * 1024,
		KeepAlivePeriod:                15 * time.Second,
		MaxIncomingStreams:             300,
		MaxIncomingUniStreams:          100,
		Allow0RTT:                      true,
		EnableDatagrams:                true,
	}
}

func validSNI(s string) bool {
	return s != "" && net.ParseIP(s) == nil
}

func pickSNI(cfg *ClientConfig) string {
	pool := make([]string, 0, len(cfg.ServerNames)+1)
	for _, s := range cfg.ServerNames {
		if validSNI(s) {
			pool = append(pool, s)
		}
	}
	if len(pool) == 0 && validSNI(cfg.ServerName) {
		pool = append(pool, cfg.ServerName)
	}
	if len(pool) == 0 {
		return ""
	}
	return pool[mrand.Intn(len(pool))]
}

func hasConfiguredSNI(cfg *ClientConfig) bool {
	for _, s := range cfg.ServerNames {
		if validSNI(s) {
			return true
		}
	}
	return validSNI(cfg.ServerName)
}

var (
	sessionSNIMu  sync.Mutex
	sessionSNIVal string
)

func sessionSNI(cfg *ClientConfig) string {
	sessionSNIMu.Lock()
	defer sessionSNIMu.Unlock()
	if sessionSNIVal != "" {
		return sessionSNIVal
	}
	s := pickSNI(cfg)
	if hasConfiguredSNI(cfg) {
		sessionSNIVal = s
	}
	return s
}

func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}
