package fingerprint

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/nekoskin/whispera/common/fsown"

	utls "github.com/refraction-networking/utls"
)

func kindFromName(name string) kind {
	switch name {
	case "firefox", "firefox_120":
		return kindFirefox
	case "safari", "ios":
		return kindSafari
	default:
		return kindChromium
	}
}

func PersistRawFingerprint(dir string, raw []byte) error {
	fp := &utls.Fingerprinter{AllowBluntMimicry: true}
	if _, err := fp.FingerprintClientHello(raw); err != nil {
		return err
	}
	key, ok := collectKey(raw)
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

func FreshestRaw(dir, kind string) ([]byte, bool) {
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
		if ClassifyClientHello(data) != want {
			continue
		}
		if best == nil || info.ModTime().After(bestMod) {
			best = data
			bestMod = info.ModTime()
		}
	}
	return best, best != nil
}

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

var collectOnce sync.Once

var (
	collectDirMu       sync.RWMutex
	collectDirOverride string
)

func SetCollectDir(dir string) {
	collectDirMu.Lock()
	collectDirOverride = dir
	collectDirMu.Unlock()
}

func collectDirPath() string {
	collectDirMu.RLock()
	d := collectDirOverride
	collectDirMu.RUnlock()
	if d != "" {
		return d
	}
	return os.Getenv("WHISPERA_FP_DIR")
}

func CollectRawClientHello(record []byte) error {
	fp := &utls.Fingerprinter{AllowBluntMimicry: true}
	spec, err := fp.FingerprintClientHello(record)
	if err != nil {
		return err
	}
	AddCollected(spec, record)
	return nil
}

func persistFingerprint(key string, raw []byte) {
	dir := collectDirPath()
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

func LoadCollectDir(dir string) (int, error) {
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
		if CollectRawClientHello(data) == nil {
			n++
		}
	}
	return n, nil
}

func initCollect() {
	loadSeedFingerprints()
	dir := collectDirPath()
	if dir == "" {
		return
	}
	_, _ = LoadCollectDir(dir)
}

func CollectFromHello(raw []byte) {
	if !looksLikeRealBrowser(raw) {
		return
	}
	dir := collectDirPath()
	if dir == "" {
		return
	}
	rawCopy := append([]byte(nil), raw...)
	go func() { _ = PersistRawFingerprint(dir, rawCopy) }()
}
