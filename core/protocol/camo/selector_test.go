package camo

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"
	"time"
)

func newEph(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("эфемерный ключ: %v", err)
	}
	return k
}

func TestSelectorRoundTrip(t *testing.T) {
	seed := make([]byte, 32)
	rand.Read(seed)
	srv, err := ServerKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("ключ сервера: %v", err)
	}

	psk := make([]byte, 32)
	rand.Read(psk)
	eph := newEph(t)

	sel, err := BuildSelector(psk, eph, srv.PublicKey())
	if err != nil {
		t.Fatalf("BuildSelector: %v", err)
	}
	got, err := OpenSelector(sel, srv, eph.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("OpenSelector: %v", err)
	}
	if got != UserTag(psk) {
		t.Fatalf("сервер не восстановил метку пользователя")
	}
}

func TestServerKeyIsDeterministic(t *testing.T) {
	seed := make([]byte, 32)
	rand.Read(seed)
	a, _ := ServerKeyFromSeed(seed)
	b, _ := ServerKeyFromSeed(seed)
	if string(a.PublicKey().Bytes()) != string(b.PublicKey().Bytes()) {
		t.Fatal("из одного сида должен получаться один и тот же ключ")
	}
}

// Главное свойство: два соединения одного пользователя не должны быть связаны
// пассивным наблюдателем — селектор рандомизируется эфемерным ключом.
func TestSelectorDiffersPerConnection(t *testing.T) {
	seed := make([]byte, 32)
	rand.Read(seed)
	srv, _ := ServerKeyFromSeed(seed)
	psk := make([]byte, 32)
	rand.Read(psk)

	first, err := BuildSelector(psk, newEph(t), srv.PublicKey())
	if err != nil {
		t.Fatalf("BuildSelector: %v", err)
	}
	second, err := BuildSelector(psk, newEph(t), srv.PublicKey())
	if err != nil {
		t.Fatalf("BuildSelector: %v", err)
	}
	if first == second {
		t.Fatal("селектор повторился между соединениями — это связываемый отпечаток")
	}
}

func TestRandomLayoutAndMarker(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)
	key := DeriveKey(psk)
	keyShare := make([]byte, 32)
	rand.Read(keyShare)

	var sel [SelectorSize]byte
	rand.Read(sel[:])

	random := make([]byte, 32)
	now := time.Now().Unix()
	if !WriteRandom(random, sel, key, now/WindowSeconds, keyShare) {
		t.Fatal("WriteRandom отказал")
	}

	gotSel, marker, ok := SplitRandom(random)
	if !ok || gotSel != sel {
		t.Fatal("селектор не выделился обратно")
	}
	if len(marker) != MarkerSize {
		t.Fatalf("маркер %d байт, ожидалось %d", len(marker), MarkerSize)
	}
	if !MarkerMatchesKey(key, marker, keyShare, now) {
		t.Fatal("маркер своего ключа не сошёлся")
	}

	other := make([]byte, 32)
	rand.Read(other)
	if MarkerMatchesKey(DeriveKey(other), marker, keyShare, now) {
		t.Fatal("маркер сошёлся с чужим ключом")
	}
}

func TestMarkerToleratesWindowDrift(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)
	key := DeriveKey(psk)
	keyShare := make([]byte, 32)
	rand.Read(keyShare)

	now := time.Now().Unix()
	random := make([]byte, 32)
	var sel [SelectorSize]byte
	WriteRandom(random, sel, key, now/WindowSeconds, keyShare)
	_, marker, _ := SplitRandom(random)

	if !MarkerMatchesKey(key, marker, keyShare, now+WindowSeconds) {
		t.Fatal("маркер должен приниматься в соседнем окне вперёд")
	}
	if !MarkerMatchesKey(key, marker, keyShare, now-WindowSeconds) {
		t.Fatal("маркер должен приниматься в соседнем окне назад")
	}
	if MarkerMatchesKey(key, marker, keyShare, now+5*WindowSeconds) {
		t.Fatal("маркер не должен приниматься далеко за окном")
	}
}
