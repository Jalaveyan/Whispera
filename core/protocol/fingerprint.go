package protocol

import (
	"encoding/binary"
	"hash/fnv"
	mrand "math/rand"
	"net"
	"sort"
	"strconv"
	"sync"

	utls "github.com/refraction-networking/utls"
)

var (
	harvestMu    sync.RWMutex
	harvestSpecs []*utls.ClientHelloSpec
	harvestRaw   [][]byte
	harvestKinds []browserKind
	harvestSeen  = map[string]bool{}
)

const maxHarvest = 32

var (
	forcedFingerprintMu sync.RWMutex
	forcedFingerprintID utls.ClientHelloID
)

var (
	forcedRawMu    sync.RWMutex
	forcedRawBytes []byte
	forcedRawKind  browserKind
)

func specFromRaw(raw []byte) (*utls.ClientHelloSpec, error) {
	fp := &utls.Fingerprinter{AllowBluntMimicry: true}
	return fp.FingerprintClientHello(raw)
}

func isPQCurve(g utls.CurveID) bool {
	return g == utls.X25519MLKEM768 || g == utls.X25519Kyber768Draft00
}

func dropPQKeyShares(spec *utls.ClientHelloSpec) {
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
	spec, err := specFromRaw(raw)
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

func SetForcedRawFingerprint(raw []byte) {
	var stored []byte
	kind := kindChromium
	if len(raw) > 0 && rawHelloReplayable(raw) && specHandshakeReadyRaw(raw) {
		stored = append([]byte(nil), raw...)
		kind = classifyClientHello(raw)
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

func IsKnownFingerprint(name string) bool {
	if name == "random" {
		return true
	}
	_, ok := namedFingerprints[name]
	return ok
}

func SetForcedFingerprint(name string) {
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
	return len(extractX25519KeyShare(hello.KeyShares)) > 0
}

func addHarvestedFingerprint(spec *utls.ClientHelloSpec, raw []byte) {
	if len(raw) == 0 || !specHandshakeReady(spec) {
		return
	}
	key, keyed := harvestKey(raw)

	harvestMu.Lock()
	if keyed && harvestSeen[key] {
		harvestMu.Unlock()
		return
	}
	added := false
	if len(harvestSpecs) < maxHarvest {
		harvestSpecs = append(harvestSpecs, spec)
		harvestRaw = append(harvestRaw, raw)
		harvestKinds = append(harvestKinds, classifyClientHello(raw))
		if keyed {
			harvestSeen[key] = true
		}
		added = true
	}
	harvestMu.Unlock()

	if added && keyed {
		persistFingerprint(key, raw)
	}
}

func harvestKey(raw []byte) (string, bool) {
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

func AddHarvestedFingerprint(spec *utls.ClientHelloSpec) {
	addHarvestedFingerprint(spec, nil)
}

func HarvestedRawRecords() [][]byte {
	harvestMu.RLock()
	defer harvestMu.RUnlock()
	out := make([][]byte, 0, len(harvestRaw))
	for _, rec := range harvestRaw {
		if rec != nil {
			out = append(out, append([]byte(nil), rec...))
		}
	}
	return out
}

func HarvestedFingerprintCount() int {
	harvestMu.RLock()
	defer harvestMu.RUnlock()
	return len(harvestSpecs)
}

func HarvestedFingerprintCapacity() int {
	return maxHarvest
}

func pickFingerprint() (id utls.ClientHelloID, raw []byte, uaID utls.ClientHelloID) {
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

	harvestOnce.Do(initHarvest)

	harvestMu.RLock()
	defer harvestMu.RUnlock()

	if len(harvestRaw) > 0 {
		i := mrand.Intn(len(harvestRaw))
		return utls.HelloCustom, append([]byte(nil), harvestRaw[i]...), repIDForKind(harvestKinds[i])
	}

	traceLog.Errorw("fingerprint_pool_empty_emergency_hello")
	return utls.HelloChrome_Auto, nil, utls.HelloChrome_Auto
}

var (
	sessionFPOnce sync.Once
	sessionFPID   utls.ClientHelloID
	sessionFPRaw  []byte
	sessionFPUA   utls.ClientHelloID
)

func sessionFingerprint() (utls.ClientHelloID, []byte, utls.ClientHelloID) {
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
		sessionFPID, sessionFPRaw, sessionFPUA = pickFingerprint()
	})
	return sessionFPID, append([]byte(nil), sessionFPRaw...), sessionFPUA
}

func repIDForKind(k browserKind) utls.ClientHelloID {
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

func classifyClientHello(raw []byte) browserKind {
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
