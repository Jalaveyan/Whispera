package protocol

import (
	"crypto/rand"
	"testing"

	"github.com/nekoskin/whispera/core/protocol/camo"
)

func psk32(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	rand.Read(b)
	return b
}

func TestSelectorIndexRebuildsOnlyWhenUsersChange(t *testing.T) {
	alice := psk32(t)
	bob := psk32(t)

	users := []UserEntry{{UserID: "alice", PSK: alice}}
	version := uint64(1)
	calls := 0

	cfg := &ServerConfig{
		GetUsers: func() []UserEntry {
			calls++
			return users
		},
		UsersVersion: func() uint64 { return version },
	}

	if _, ok := cfg.selectors.snapshot(cfg)[camo.UserTag(alice)]; !ok {
		t.Fatal("alice должна попасть в индекс")
	}
	if calls != 1 {
		t.Fatalf("ожидалась одна сборка, было %d", calls)
	}

	for i := 0; i < 50; i++ {
		cfg.selectors.snapshot(cfg)
	}
	if calls != 1 {
		t.Fatalf("версия не менялась, а индекс пересобирался %d раз", calls)
	}

	users = append(users, UserEntry{UserID: "bob", PSK: bob})
	version++

	idx := cfg.selectors.snapshot(cfg)
	if calls != 2 {
		t.Fatalf("после смены версии ожидалась пересборка, сборок %d", calls)
	}
	if entry, ok := idx[camo.UserTag(bob)]; !ok || entry.userID != "bob" {
		t.Fatal("новый пользователь не появился в индексе")
	}
}

func TestSelectorIndexFallsBackToTTLWithoutVersion(t *testing.T) {
	alice := psk32(t)
	calls := 0
	cfg := &ServerConfig{
		GetUsers: func() []UserEntry {
			calls++
			return []UserEntry{{UserID: "alice", PSK: alice}}
		},
	}
	cfg.selectors.snapshot(cfg)
	cfg.selectors.snapshot(cfg)
	if calls != 1 {
		t.Fatalf("без версии индекс должен держаться по TTL, сборок %d", calls)
	}
}

func TestResolveSecretForUsesKnownUser(t *testing.T) {
	known := psk32(t)
	other := psk32(t)

	noScan := &ServerConfig{
		GetUsers: func() []UserEntry {
			t.Fatal("перебор не должен запускаться, когда токен сошёлся с опознанным пользователем")
			return nil
		},
	}

	sessionID := make([]byte, 16)
	rand.Read(sessionID)
	token := ClientAuthToken(DeriveKeys(known).Auth, sessionID)

	secret, userID := resolveSecretFor(noScan, knownUser{id: "alice", psk: known}, token, sessionID)
	if userID != "alice" || string(secret) != string(known) {
		t.Fatalf("ожидалась alice по быстрому пути, получено %q", userID)
	}

	scanned := 0
	withScan := &ServerConfig{
		GetUsers: func() []UserEntry {
			scanned++
			return nil
		},
	}
	foreign := ClientAuthToken(DeriveKeys(other).Auth, sessionID)
	if _, id := resolveSecretFor(withScan, knownUser{id: "alice", psk: known}, foreign, sessionID); id != "" {
		t.Fatal("чужой токен не должен приниматься")
	}
	if scanned == 0 {
		t.Fatal("при несошедшемся токене должен быть откат на перебор")
	}
}
