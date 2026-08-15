package fingerprint

import (
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/nekoskin/whispera/core/protocol/camo"

	utls "github.com/refraction-networking/utls"
)

// A harvested pool is finite: collect enough of it and every fingerprint we can
// present is known. Recombining it is not — the extensions are real, taken whole
// from browsers that sent them, but the set and the order are ours. Each one is
// placed where the pool usually carries it, so the result reads like a client
// rather than like a shuffle.
//
// The fingerprint is per device, not per connection. A host presenting a new
// JA3 every time is louder than one presenting a stale one: people run one
// browser, not a thousand.

const (
	extSNI            = 0
	extSupportedGroup = 10
	extSigAlgs        = 13
	extPreSharedKey   = 41
	extSupportedVers  = 43
	extKeyShare       = 51
	genAttempts       = 64
)

var required = []uint16{extSNI, extSupportedGroup, extSigAlgs, extSupportedVers, extKeyShare}

type extBank struct {
	byType map[uint16][]utls.TLSExtension
	place  map[uint16]float64
	order  [][]uint16
	suites [][]uint16
}

// extType reads an extension's own two-byte type off its wire form. Read follows
// io.Reader and reports io.EOF once it has written everything, which is success.
func extType(e utls.TLSExtension) (uint16, bool) {
	buf := make([]byte, e.Len())
	n, err := e.Read(buf)
	if (err != nil && err != io.EOF) || n < 2 {
		return 0, false
	}
	return uint16(buf[0])<<8 | uint16(buf[1]), true
}

func buildBank(specs []*utls.ClientHelloSpec) *extBank {
	b := &extBank{byType: map[uint16][]utls.TLSExtension{}, place: map[uint16]float64{}}
	seen := map[uint16][]float64{}
	for _, s := range specs {
		if s == nil {
			continue
		}
		var types []uint16
		for _, e := range s.Extensions {
			t, ok := extType(e)
			if !ok {
				continue
			}
			b.byType[t] = append(b.byType[t], e)
			types = append(types, t)
		}
		if len(types) == 0 {
			continue
		}
		for i, t := range types {
			seen[t] = append(seen[t], float64(i)/float64(len(types)))
		}
		b.order = append(b.order, types)
		b.suites = append(b.suites, append([]uint16(nil), s.CipherSuites...))
	}
	for t, at := range seen {
		sum := 0.0
		for _, v := range at {
			sum += v
		}
		b.place[t] = sum / float64(len(at))
	}
	return b
}

// compose draws a set of extensions from what the pool offers and lays them out
// in the order browsers usually carry them. pre_shared_key is left out: it is
// only valid last, and a hello that has it anywhere else fails outright.
func (b *extBank) compose(rng *mrand.Rand) []uint16 {
	donor := b.order[rng.Intn(len(b.order))]
	picked := map[uint16]bool{}
	for _, t := range donor {
		if t != extPreSharedKey {
			picked[t] = true
		}
	}
	// Borrow a few extensions from the other donors, and drop a few of this
	// one's — that is where combinations beyond the pool come from.
	for t := range b.byType {
		if t == extPreSharedKey {
			continue
		}
		if rng.Intn(4) == 0 {
			picked[t] = !picked[t]
		}
	}
	for _, t := range required {
		if len(b.byType[t]) > 0 {
			picked[t] = true
		}
	}

	out := make([]uint16, 0, len(picked))
	for t, in := range picked {
		if in {
			out = append(out, t)
		}
	}
	sortByPlace(out, b.place)
	return out
}

func sortByPlace(types []uint16, place map[uint16]float64) {
	for i := 1; i < len(types); i++ {
		for j := i; j > 0 && place[types[j]] < place[types[j-1]]; j-- {
			types[j], types[j-1] = types[j-1], types[j]
		}
	}
}

func (b *extBank) assemble(types []uint16, rng *mrand.Rand) *utls.ClientHelloSpec {
	exts := make([]utls.TLSExtension, 0, len(types))
	for _, t := range types {
		pool := b.byType[t]
		if len(pool) == 0 {
			return nil
		}
		exts = append(exts, pool[rng.Intn(len(pool))])
	}
	return &utls.ClientHelloSpec{
		CipherSuites: append([]uint16(nil), b.suites[rng.Intn(len(b.suites))]...),
		Extensions:   exts,
	}
}

// Generate returns a ClientHello no browser sent but that reads like one: every
// extension is genuine, the layout follows the pool, and it is rejected unless
// it can actually build a handshake.
func Generate(seed int64) ([]byte, error) {
	collectOnce.Do(initCollect)

	collectMu.RLock()
	specs := append([]*utls.ClientHelloSpec(nil), collectSpecs...)
	collectMu.RUnlock()

	if len(specs) < 2 {
		return nil, fmt.Errorf("fingerprint: pool holds %d specs, need 2 to recombine", len(specs))
	}
	bank := buildBank(specs)
	if len(bank.order) == 0 {
		return nil, fmt.Errorf("fingerprint: no extensions in pool")
	}

	rng := mrand.New(mrand.NewSource(seed))
	for i := 0; i < genAttempts; i++ {
		spec := bank.assemble(bank.compose(rng), rng)
		if spec == nil {
			continue
		}
		raw, err := specRaw(spec)
		if err != nil {
			continue
		}
		return raw, nil
	}
	return nil, fmt.Errorf("fingerprint: %d attempts produced no usable hello", genAttempts)
}

// specRaw builds the hello the way the dialer will, so a spec that cannot reach
// the wire is caught here and not on a user's connection.
func specRaw(spec *utls.ClientHelloSpec) ([]byte, error) {
	c0, c1 := net.Pipe()
	defer c0.Close()
	defer c1.Close()

	u := utls.UClient(c0, &utls.Config{
		ServerName:                         "example.com",
		InsecureSkipVerify:                 true,
		PreferSkipResumptionOnNilExtension: true,
	}, utls.HelloCustom)
	if err := u.ApplyPreset(spec); err != nil {
		return nil, err
	}
	if err := u.BuildHandshakeState(); err != nil {
		return nil, err
	}
	hello := u.HandshakeState.Hello
	if hello == nil || len(hello.Raw) == 0 {
		return nil, fmt.Errorf("fingerprint: empty hello")
	}
	if len(camo.ExtractX25519KeyShare(hello.KeyShares)) == 0 {
		return nil, fmt.Errorf("fingerprint: no usable key share")
	}
	return asRecord(hello.Raw), nil
}

// asRecord wraps a handshake message in the record layer: the pool stores whole
// records, and a bare handshake would be rejected by anything parsing it back.
func asRecord(handshake []byte) []byte {
	rec := make([]byte, 5+len(handshake))
	rec[0], rec[1], rec[2] = 0x16, 0x03, 0x01
	rec[3] = byte(len(handshake) >> 8)
	rec[4] = byte(len(handshake))
	copy(rec[5:], handshake)
	return rec
}

var (
	deviceOnce sync.Once
	deviceRaw  []byte
	deviceKind kind
)

// DeviceHello is the generated fingerprint this install presents, or nothing if
// the pool is too small to recombine — in which case the caller keeps to a
// harvested hello, worse only in that its pool is finite.
// Generating reports whether this install was asked to make its own hello.
//
// Callers that would otherwise force a named fingerprint have to ask: the flag
// that selects one defaults to "chrome", so it is always set even when nobody
// chose it, and pick() consults the forced name before it gets anywhere near a
// generated hello. That ordering made WHISPERA_GEN_HELLO unreachable in the
// client — the generator worked, and nothing ever called it.
func Generating() bool { return os.Getenv("WHISPERA_GEN_HELLO") != "0" }

func DeviceHello() ([]byte, kind, bool) {
	deviceOnce.Do(func() {
		if !Generating() {
			return
		}
		dir := collectDirPath()
		if dir == "" {
			return
		}
		raw, err := DeviceFingerprint(filepath.Join(dir, "device.hello"))
		if err != nil {
			traceLog.Errorw("fingerprint_generate_failed", "err", err.Error())
			return
		}
		deviceRaw, deviceKind = raw, ClassifyClientHello(raw)
		traceLog.Infow("fingerprint_generated", "bytes", len(raw))
	})
	if len(deviceRaw) == 0 {
		return nil, 0, false
	}
	return append([]byte(nil), deviceRaw...), deviceKind, true
}

// DeviceFingerprint makes this install's hello once and keeps it. Regenerating
// from a seed would not do: the pool it recombines grows as more hellos are
// harvested, so the same seed stops meaning the same fingerprint.
func DeviceFingerprint(path string) ([]byte, error) {
	if path != "" {
		if raw, err := os.ReadFile(path); err == nil && len(raw) > 0 {
			if _, perr := SpecFromRaw(raw); perr == nil {
				return raw, nil
			}
		}
	}
	raw, err := Generate(time.Now().UnixNano())
	if err != nil {
		return nil, err
	}
	if path == "" {
		return raw, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return raw, nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err == nil {
		_ = os.Rename(tmp, path)
	}
	return raw, nil
}
