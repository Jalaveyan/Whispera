package protocol

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

func benchUsers(n int) []UserEntry {
	users := make([]UserEntry, n)
	for i := range users {
		psk := make([]byte, 32)
		rand.Read(psk)
		users[i] = UserEntry{UserID: fmt.Sprintf("user-%d", i), PSK: psk}
	}
	return users
}

func benchConfig(users []UserEntry) *ServerConfig {
	return &ServerConfig{GetUsers: func() []UserEntry { return users }}
}

// resolveSecret перебирает пользователей линейно, а при неудаче ещё раз —
// через probeClockDriftOnFailure, который щупает по 18 окон на пользователя.
// Интересно, во сколько раз промах дороже попадания и как это растёт от числа ключей.
func BenchmarkResolveSecret(b *testing.B) {
	for _, n := range []int{1, 10, 100, 1000} {
		users := benchUsers(n)
		cfg := benchConfig(users)
		sessionID := make([]byte, 16)
		rand.Read(sessionID)
		window := time.Now().UTC().Truncate(time.Second).Unix() / authWindowSeconds

		last := DeriveKeys(users[n-1].PSK)
		hit := AuthToken(last.Auth, window, sessionID)

		b.Run(fmt.Sprintf("hit_last/users=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, id := resolveSecret(cfg, hit, sessionID); id == "" {
					b.Fatal("должен был найтись")
				}
			}
		})

		miss := AuthToken(last.Auth, window+50, sessionID)
		b.Run(fmt.Sprintf("miss/users=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, id := resolveSecret(cfg, miss, sessionID); id != "" {
					b.Fatal("не должен был найтись")
				}
			}
		})
	}
}
