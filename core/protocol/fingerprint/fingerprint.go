package fingerprint

import (
	"encoding/binary"
	logger "github.com/nekoskin/whispera/common/log"
	"hash/fnv"
	mrand "math/rand"
	"net"
	"sort"
	"strconv"
	"sync"

	"github.com/nekoskin/whispera/core/protocol/camo"

	utls "github.com/refraction-networking/utls"
)

var (
	collectMu    sync.RWMutex
	collectSpecs []*utls.ClientHelloSpec
	collectRaw   [][]byte
	collectKinds []kind
	collectSeen  = map[string]bool{}
)

const maxCollect = 32

var (
	forcedFingerprintMu sync.RWMutex
	forcedFingerprintID utls.ClientHelloID
)

var (
	forcedRawMu    sync.RWMutex
	forcedRawBytes []byte
	forcedRawKind  kind
)

func SpecFromRaw(raw []byte) (*utls.ClientHelloSpec, error) {
	fp := &utls.Fingerprinter{AllowBluntMimicry: true}
	return fp.FingerprintClientHello(raw)
}

func isPQCurve(g utls.CurveID) bool {
	return g == utls.X25519MLKEM768 || g == utls.X25519Kyber768Draft00
}

func DropPQKeyShares(spec *utls.ClientHelloSpec) {
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.KeyShareExtension:
			kept := e.KeyShares[:0]
			for _, k := range e.KeyShares {
				if isPQCurve(k.Group) {
					continue
				}
				if k.Group != utls.GREASE_PLACEHOLDER && len(k.Data) > 0 {
					k.Data = nil
				}
				kept = append(kept, k)
			}
			e.KeyShares = kept
		case *utls.SupportedCurvesExtension:
			kept := e.Curves[:0]
			for _, c := range e.Curves {
				if !isPQCurve(c) {
					kept = append(kept, c)
				}
			}
			e.Curves = kept
		}
	}
}

func specHandshakeReadyRaw(raw []byte) bool {
	spec, err := SpecFromRaw(raw)
	if err != nil {
		return false
	}
	return specHandshakeReady(spec)
}

func rawHelloReplayable(raw []byte) bool {
	hs := raw
	if len(hs) >= 5 && hs[0] == 0x16 {
		hs = hs[5:]
	}
	msg := utls.UnmarshalClientHello(hs)
	if msg == nil {
		return false
	}
	for _, ks := range msg.KeyShares {
		if ks.Group == utls.X25519MLKEM768 || ks.Group == utls.X25519Kyber768Draft00 {
			return false
		}
	}
	return true
}

func SetForcedRaw(raw []byte) {
	var stored []byte
	kind := kindChromium
	if len(raw) > 0 && rawHelloReplayable(raw) && specHandshakeReadyRaw(raw) {
		stored = append([]byte(nil), raw...)
		kind = ClassifyClientHello(raw)
	}
	forcedRawMu.Lock()
	forcedRawBytes = stored
	forcedRawKind = kind
	forcedRawMu.Unlock()
}

var namedFingerprints = map[string]utls.ClientHelloID{
	"chrome":      utls.HelloChrome_Auto,
	"chrome_120":  utls.HelloChrome_120,
	"chrome_115":  utls.HelloChrome_115_PQ,
	"firefox":     utls.HelloFirefox_Auto,
	"firefox_120": utls.HelloFirefox_120,
	"safari":      utls.HelloSafari_Auto,
	"ios":         utls.HelloIOS_Auto,
	"android":     utls.HelloAndroid_11_OkHttp,
	"edge":        utls.HelloEdge_Auto,
}

func IsKnown(name string) bool {
	if name == "random" {
		return true
	}
	_, ok := namedFingerprints[name]
	return ok
}

func SetForced(name string) {
	id, ok := namedFingerprints[name]
	forcedFingerprintMu.Lock()
	defer forcedFingerprintMu.Unlock()
	if !ok {
		forcedFingerprintID = utls.ClientHelloID{}
		return
	}
	forcedFingerprintID = id
}

func specHandshakeReady(spec *utls.ClientHelloSpec) bool {
	if spec == nil {
		return false
	}
	c0, c1 := net.Pipe()
	defer c0.Close()
	defer c1.Close()
	u := utls.UClient(c0, &utls.Config{
		ServerName:                         "example.com",
		InsecureSkipVerify:                 true,
		PreferSkipResumptionOnNilExtension: true,
	}, utls.HelloCustom)
	if err := u.ApplyPreset(spec); err != nil {
		return false
	}
	if err := u.BuildHandshakeState(); err != nil {
		return false
	}
	hello := u.HandshakeState.Hello
	if hello == nil || len(hello.Random) != 32 {
		return false
	}
	return len(camo.ExtractX25519KeyShare(hello.KeyShares)) > 0
}

func AddCollected(spec *utls.ClientHelloSpec, raw []byte) {
	if len(raw) == 0 || !specHandshakeReady(spec) {
		return
	}
	key, keyed := collectKey(raw)

	collectMu.Lock()
	if keyed && collectSeen[key] {
		collectMu.Unlock()
		return
	}
	added := false
	if len(collectSpecs) < maxCollect {
		collectSpecs = append(collectSpecs, spec)
		collectRaw = append(collectRaw, raw)
		collectKinds = append(collectKinds, ClassifyClientHello(raw))
		if keyed {
			collectSeen[key] = true
		}
		added = true
	}
	collectMu.Unlock()

	if added && keyed {
		persistFingerprint(key, raw)
	}
}

func collectKey(raw []byte) (string, bool) {
	exts, ok := clientHelloExtTypes(raw)
	if !ok {
		return "", false
	}
	norm := make([]uint16, len(exts))
	for i, t := range exts {
		if isGREASE(t) {
			t = 0x0a0a
		}
		norm[i] = t
	}
	sort.Slice(norm, func(i, j int) bool { return norm[i] < norm[j] })

	h := fnv.New64a()
	var b [2]byte
	for _, t := range norm {
		binary.BigEndian.PutUint16(b[:], t)
		_, _ = h.Write(b[:])
	}
	return strconv.FormatUint(h.Sum64(), 16), true
}

func CollectedCount() int {
	collectMu.RLock()
	defer collectMu.RUnlock()
	return len(collectSpecs)
}

func CollectedCapacity() int {
	return maxCollect
}

func pick() (id utls.ClientHelloID, raw []byte, uaID utls.ClientHelloID) {
	forcedRawMu.RLock()
	fraw := forcedRawBytes
	rawKind := forcedRawKind
	forcedRawMu.RUnlock()
	if len(fraw) > 0 {
		return utls.HelloCustom, append([]byte(nil), fraw...), repIDForKind(rawKind)
	}

	forcedFingerprintMu.RLock()
	forced := forcedFingerprintID
	forcedFingerprintMu.RUnlock()
	if forced.Client != "" {
		return forced, nil, forced
	}

	collectOnce.Do(initCollect)

	// A generated hello if asked for: the harvested pool is finite and can be
	// collected, a recombination of it cannot.
	if raw, k, ok := DeviceHello(); ok {
		return utls.HelloCustom, raw, repIDForKind(k)
	}

	collectMu.RLock()
	defer collectMu.RUnlock()

	if len(collectRaw) > 0 {
		i := mrand.Intn(len(collectRaw))
		return utls.HelloCustom, append([]byte(nil), collectRaw[i]...), repIDForKind(collectKinds[i])
	}

	traceLog.Errorw("fingerprint_pool_empty_emergency_hello")
	return utls.HelloChrome_Auto, nil, utls.HelloChrome_Auto
}

// presets is the controller's repertoire: real, uTLS-maintained browser
// fingerprints. Unlike a frozen harvested capture, uTLS keeps these current with
// the browser, and each one sets its own SNI correctly. The controller picks
// among them by index under the live signal.
var presets = []utls.ClientHelloID{
	utls.HelloChrome_Auto,
	utls.HelloFirefox_Auto,
	utls.HelloSafari_Auto,
	utls.HelloIOS_Auto,
	utls.HelloEdge_Auto,
}

func PresetCount() int { return len(presets) }

func PresetAt(i int) utls.ClientHelloID {
	if i < 0 || i >= len(presets) {
		return utls.HelloChrome_Auto
	}
	return presets[i]
}

// PoolSize is how many real (seed + harvested) fingerprints the controller can
// choose between. These are captured whole from real clients, not recombined.
func PoolSize() int {
	collectOnce.Do(initCollect)
	collectMu.RLock()
	defer collectMu.RUnlock()
	return len(collectRaw)
}

// RawAt returns the i-th real fingerprint from the pool, for a controller that
// picks by index instead of at random. Out of range falls back to Chrome.
func RawAt(i int) (utls.ClientHelloID, []byte, utls.ClientHelloID) {
	collectOnce.Do(initCollect)
	collectMu.RLock()
	defer collectMu.RUnlock()
	if i < 0 || i >= len(collectRaw) {
		return utls.HelloChrome_Auto, nil, utls.HelloChrome_Auto
	}
	return utls.HelloCustom, append([]byte(nil), collectRaw[i]...), repIDForKind(collectKinds[i])
}

var (
	sessionFPOnce sync.Once
	sessionFPID   utls.ClientHelloID
	sessionFPRaw  []byte
	sessionFPUA   utls.ClientHelloID
)

func Session() (utls.ClientHelloID, []byte, utls.ClientHelloID) {
	forcedRawMu.RLock()
	fraw := forcedRawBytes
	rawKind := forcedRawKind
	forcedRawMu.RUnlock()
	if len(fraw) > 0 {
		return utls.HelloCustom, append([]byte(nil), fraw...), repIDForKind(rawKind)
	}

	forcedFingerprintMu.RLock()
	forced := forcedFingerprintID
	forcedFingerprintMu.RUnlock()
	if forced.Client != "" {
		return forced, nil, forced
	}

	sessionFPOnce.Do(func() {
		sessionFPID, sessionFPRaw, sessionFPUA = pick()
	})
	return sessionFPID, append([]byte(nil), sessionFPRaw...), sessionFPUA
}

func repIDForKind(k kind) utls.ClientHelloID {
	switch k {
	case kindFirefox:
		return utls.HelloFirefox_148
	case kindSafari:
		return utls.HelloSafari_16_0
	default:
		return utls.HelloChrome_133
	}
}

const (
	extRecordSizeLimit = 0x001c
	extALPSOld         = 0x4469
	extALPSNew         = 0x44cd
)

func ClassifyClientHello(raw []byte) kind {
	exts, ok := clientHelloExtTypes(raw)
	if !ok {
		return kindChromium
	}
	hasGREASE := false
	for _, t := range exts {
		switch {
		case t == extRecordSizeLimit:
			return kindFirefox
		case t == extALPSOld, t == extALPSNew:
			return kindChromium
		case isGREASE(t):
			hasGREASE = true
		}
	}
	if hasGREASE {
		return kindSafari
	}
	return kindChromium
}

func isGREASE(v uint16) bool {
	return byte(v>>8) == byte(v) && v&0x0f0f == 0x0a0a
}

func clientHelloExtTypes(raw []byte) ([]uint16, bool) {
	b := raw
	if len(b) >= 5 && b[0] == 0x16 {
		b = b[5:]
	}
	if len(b) < 4 || b[0] != 0x01 {
		return nil, false
	}
	b = b[4:]

	if len(b) < 34 {
		return nil, false
	}
	b = b[34:]

	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return nil, false
	}
	b = b[1+int(b[0]):]

	if len(b) < 2 {
		return nil, false
	}
	csLen := int(b[0])<<8 | int(b[1])
	if len(b) < 2+csLen {
		return nil, false
	}
	b = b[2+csLen:]

	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return nil, false
	}
	b = b[1+int(b[0]):]

	if len(b) < 2 {
		return nil, false
	}
	extTotal := int(b[0])<<8 | int(b[1])
	b = b[2:]
	if len(b) < extTotal {
		extTotal = len(b)
	}
	b = b[:extTotal]

	var types []uint16
	for len(b) >= 4 {
		t := uint16(b[0])<<8 | uint16(b[1])
		l := int(b[2])<<8 | int(b[3])
		types = append(types, t)
		if len(b) < 4+l {
			break
		}
		b = b[4+l:]
	}
	return types, true
}

var traceLog = logger.Trace()
