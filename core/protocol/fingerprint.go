package protocol

import (
	"encoding/binary"
	"hash/fnv"
	mrand "math/rand"
	"sort"
	"strconv"
	"sync"

	utls "github.com/refraction-networking/utls"
)

var fingerprintPool = []utls.ClientHelloID{
	utls.HelloChrome_133,
	utls.HelloChrome_131,
	utls.HelloChrome_120_PQ,
	utls.HelloFirefox_148,
	utls.HelloFirefox_120,
	utls.HelloEdge_106,
	utls.HelloSafari_26_3,
	utls.HelloSafari_16_0,
	utls.HelloIOS_14,
}

var (
	harvestMu    sync.RWMutex
	harvestSpecs []*utls.ClientHelloSpec
	harvestRaw   [][]byte
	harvestKinds []browserKind
	harvestSeen  = map[string]bool{}
)

var detectedBrowserID utls.ClientHelloID

const maxHarvest = 32

var (
	forcedFingerprintMu sync.RWMutex
	forcedFingerprintID utls.ClientHelloID
)

var (
	forcedRawMu   sync.RWMutex
	forcedRawSpec *utls.ClientHelloSpec
	forcedRawKind browserKind
)

// SetForcedRawFingerprint pins an exact captured ClientHello (raw record) for
// the tunnel handshake, parsed once. Takes priority over any named fingerprint.
func SetForcedRawFingerprint(raw []byte) {
	var spec *utls.ClientHelloSpec
	kind := kindChromium
	if len(raw) > 0 {
		fp := &utls.Fingerprinter{AllowBluntMimicry: true}
		if s, err := fp.FingerprintClientHello(raw); err == nil {
			spec = s
			kind = classifyClientHello(raw)
		}
	}
	forcedRawMu.Lock()
	forcedRawSpec = spec
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

func addHarvestedFingerprint(spec *utls.ClientHelloSpec, raw []byte) {
	if spec == nil {
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

func pickFingerprint() (id utls.ClientHelloID, spec *utls.ClientHelloSpec, uaID utls.ClientHelloID) {
	forcedRawMu.RLock()
	rawSpec := forcedRawSpec
	rawKind := forcedRawKind
	forcedRawMu.RUnlock()
	if rawSpec != nil {
		return utls.HelloCustom, rawSpec, repIDForKind(rawKind)
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

	if len(harvestSpecs) > 0 {
		i := mrand.Intn(len(harvestSpecs))
		return utls.HelloCustom, harvestSpecs[i], repIDForKind(harvestKinds[i])
	}

	if detectedBrowserID.Client != "" {
		return detectedBrowserID, nil, detectedBrowserID
	}

	picked := fingerprintPool[mrand.Intn(len(fingerprintPool))]
	return picked, nil, picked
}

var (
	sessionFPOnce sync.Once
	sessionFPID   utls.ClientHelloID
	sessionFPSpec *utls.ClientHelloSpec
	sessionFPUA   utls.ClientHelloID
)

func sessionFingerprint() (utls.ClientHelloID, *utls.ClientHelloSpec, utls.ClientHelloID) {
	forcedRawMu.RLock()
	rawSpec := forcedRawSpec
	rawKind := forcedRawKind
	forcedRawMu.RUnlock()
	if rawSpec != nil {
		return utls.HelloCustom, rawSpec, repIDForKind(rawKind)
	}

	forcedFingerprintMu.RLock()
	forced := forcedFingerprintID
	forcedFingerprintMu.RUnlock()
	if forced.Client != "" {
		return forced, nil, forced
	}

	sessionFPOnce.Do(func() {
		sessionFPID, sessionFPSpec, sessionFPUA = pickFingerprint()
	})
	return sessionFPID, sessionFPSpec, sessionFPUA
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
