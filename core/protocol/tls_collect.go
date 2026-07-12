package protocol

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
	"whispera/common/fsown"

	utls "github.com/refraction-networking/utls"
)

func kindFromName(name string) browserKind {
	switch name {
	case "firefox", "firefox_120":
		return kindFirefox
	case "safari", "ios":
		return kindSafari
	default:
		return kindChromium
	}
}

// PersistRawFingerprint validates a raw ClientHello record and writes it to the
// store dir (deduped by extension-set hash, mtime bumped to now so "freshest"
// reflects the latest capture). Server-side store for embedding into new keys.
func PersistRawFingerprint(dir string, raw []byte) error {
	fp := &utls.Fingerprinter{AllowBluntMimicry: true}
	if _, err := fp.FingerprintClientHello(raw); err != nil {
		return err
	}
	key, ok := harvestKey(raw)
	if !ok {
		return fmt.Errorf("whispera: not a client hello")
	}
	if dir == "" {
		return fmt.Errorf("whispera: no fingerprint store dir")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, key+".bin")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	now := time.Now()
	_ = os.Chtimes(path, now, now)
	fsown.MatchParent(path)
	return nil
}

// FreshestRawFingerprint returns the most recently stored raw ClientHello whose
// browser class matches kind ("chrome", "firefox", "safari"), by file mtime.
func FreshestRawFingerprint(dir, kind string) ([]byte, bool) {
	if dir == "" {
		return nil, false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, false
	}
	want := kindFromName(kind)
	var best []byte
	var bestMod time.Time
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".bin" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		if classifyClientHello(data) != want {
			continue
		}
		if best == nil || info.ModTime().After(bestMod) {
			best = data
			bestMod = info.ModTime()
		}
	}
	return best, best != nil
}

// looksLikeRealBrowser is a cheap filter for auto-harvest: real Chrome/Firefox/
// Safari send GREASE; most scanners/bots do not.
func looksLikeRealBrowser(raw []byte) bool {
	exts, ok := clientHelloExtTypes(raw)
	if !ok {
		return false
	}
	for _, t := range exts {
		if isGREASE(t) {
			return true
		}
	}
	return false
}

var harvestOnce sync.Once

var (
	harvestDirMu       sync.RWMutex
	harvestDirOverride string
)

// SetHarvestDir points fingerprint persistence/loading at a writable directory
// (the client's data dir). Falls back to WHISPERA_FP_DIR when unset.
func SetHarvestDir(dir string) {
	harvestDirMu.Lock()
	harvestDirOverride = dir
	harvestDirMu.Unlock()
}

func harvestDirPath() string {
	harvestDirMu.RLock()
	d := harvestDirOverride
	harvestDirMu.RUnlock()
	if d != "" {
		return d
	}
	return os.Getenv("WHISPERA_FP_DIR")
}

func HarvestRawClientHello(record []byte) error {
	fp := &utls.Fingerprinter{AllowBluntMimicry: true}
	spec, err := fp.FingerprintClientHello(record)
	if err != nil {
		return err
	}
	addHarvestedFingerprint(spec, record)
	return nil
}

// persistFingerprint writes a new unique ClientHello to disk so harvested
// fingerprints are not lost on restart. Atomic (temp + rename); a no-op when no
// harvest dir is configured or the file already exists.
func persistFingerprint(key string, raw []byte) {
	dir := harvestDirPath()
	if dir == "" || len(raw) == 0 {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	path := filepath.Join(dir, key+".bin")
	if _, err := os.Stat(path); err == nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

func LoadHarvestDir(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".bin" {
			continue
		}
		data, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			continue
		}
		if HarvestRawClientHello(data) == nil {
			n++
		}
	}
	return n, nil
}

func initHarvest() {
	loadSeedFingerprints()
	dir := harvestDirPath()
	if dir == "" {
		return
	}
	_, _ = LoadHarvestDir(dir)
}
