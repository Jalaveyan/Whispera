package wiraid

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// findExamplesDir поднимается вверх от cwd пока не найдёт examples/wiraid/.
// Иначе go test ./... падает с относительным путём.
func findExamplesDir(t *testing.T) string {
	t.Helper()
	dir, _ := os.Getwd()
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "examples", "wiraid")
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			return candidate
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("examples/wiraid not found — пропускаю смок-тест")
	return ""
}

// Все 22+ example модулей должны парситься без ошибок. Если кто-то добавил
// сломанный module.json — этот тест моментально его поймает.
func TestParseAllExampleManifests(t *testing.T) {
	root := findExamplesDir(t)
	if root == "" {
		return
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("readdir %s: %v", root, err)
	}

	parsed := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		modDir := filepath.Join(root, e.Name())
		manifestPath := filepath.Join(modDir, "module.json")
		if _, err := os.Stat(manifestPath); err != nil {
			continue
		}

		m, err := LoadManifest(modDir)
		if err != nil {
			t.Errorf("LoadManifest(%s): %v", e.Name(), err)
			continue
		}
		if m.Module.Name == "" {
			t.Errorf("%s: module.name empty", e.Name())
		}
		if m.Schema < 1 || m.Schema > 2 {
			t.Errorf("%s: schema = %d (want 1 или 2)", e.Name(), m.Schema)
		}
		// V2-апгрейд должен дать runtime.cmd.
		if len(m.Runtime.Cmd) == 0 {
			t.Errorf("%s: runtime.cmd empty after UpgradeToV2", e.Name())
		}
		parsed++
	}

	if parsed == 0 {
		t.Fatalf("0 manifests parsed — examples dir empty?")
	}
	t.Logf("parsed %d example manifests", parsed)
}

// Smoke: новый Engine на tempdir поднимается, list пустой.
func TestEngineNewEmpty(t *testing.T) {
	dir := t.TempDir()
	e, err := NewEngine(dir)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if e.Registry == nil {
		t.Fatal("Registry nil")
	}
	if got := len(e.Registry.List()); got != 0 {
		t.Errorf("empty engine: registry size = %d want 0", got)
	}
}

// Полный round-trip: LoadManifest → Registry.Add → Validate. Имитирует
// внутреннюю работу `whispera wiraid install ./path` (git clone отдельно
// тестировать здесь не имеет смысла, это Git, не наш код).
//
// Заодно фиксирует баг: InstallFromURL не поддерживает локальные пути,
// хотя README это обещает. Если когда-нибудь починят — этот тест останется
// валидным контрактом, а можно добавить отдельный TestInstallFromLocalDir.
func TestInstallExampleAndValidate(t *testing.T) {
	root := findExamplesDir(t)
	if root == "" {
		return
	}
	src := filepath.Join(root, "xray-client")
	if _, err := os.Stat(filepath.Join(src, "module.json")); err != nil {
		t.Skipf("xray-client example missing: %v", err)
	}

	e, err := NewEngine(t.TempDir())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Копируем example в registry baseDir (имитация того, что делает install).
	dst := filepath.Join(e.Registry.BaseDir(), "xray-client")
	if err := copyTree(src, dst); err != nil {
		t.Fatalf("copyTree: %v", err)
	}
	manifest, err := LoadManifest(dst)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	im := &InstalledModule{Manifest: manifest, Dir: dst}
	if err := e.Registry.Add(im); err != nil {
		t.Fatalf("Registry.Add: %v", err)
	}

	if got := len(e.Registry.List()); got != 1 {
		t.Errorf("after install: registry size = %d want 1", got)
	}

	rep, err := e.Validate("xray-client")
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if rep.Name != "xray-client" {
		t.Errorf("validate name = %q want xray-client", rep.Name)
	}
	// xray-client требует server_host/uuid/sni/etc — без params всё в MissingParam.
	if len(rep.MissingParam) == 0 {
		t.Errorf("xray-client without params: MissingParam expected non-empty, got %+v", rep.MissingParam)
	}
	// Шаблон должен отрендериться даже с пустыми params (placeholders остаются).
	if !strings.Contains(rep.ConfigSample, "vless") {
		t.Errorf("config sample must contain 'vless' for xray-client, got: %s", rep.ConfigSample)
	}
}

// copyTree рекурсивно копирует src → dst. Не импортируем сторонний пакет
// чтобы тесты остались самодостаточными.
func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode())
	})
}
