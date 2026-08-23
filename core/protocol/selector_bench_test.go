package protocol

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/nekoskin/whispera/core/protocol/camo"
)

type benchUser struct {
	id      string
	psk     []byte
	camoKey []byte
	authKey []byte
}

func makeUsers(n int) []benchUser {
	users := make([]benchUser, n)
	for i := range users {
		psk := make([]byte, 32)
		rand.Read(psk)
		users[i] = benchUser{
			id:      fmt.Sprintf("user-%d", i),
			psk:     psk,
			camoKey: camo.DeriveKey(psk),
			authKey: DeriveKeys(psk).Auth,
		}
	}
	return users
}

func window() int64 { return time.Now().Unix() / authWindowSeconds }

func currentIdentify(users []benchUser, random, keyShare []byte, token string, sessionID []byte) string {
	keys := make([][]byte, 0, len(users))
	for _, u := range users {
		keys = append(keys, camo.DeriveKey(u.psk))
	}
	if !camo.MarkerMatches(keys, random, keyShare) {
		return ""
	}
	for _, u := range users {
		if VerifyAuthToken(DeriveKeys(u.psk).Auth, token, sessionID) {
			return u.id
		}
	}
	return ""
}

func windowTag(camoKey []byte, w int64) [8]byte {
	mac := hmac.New(sha256.New, camoKey)
	var wb [8]byte
	binary.BigEndian.PutUint64(wb[:], uint64(w))
	mac.Write([]byte("id"))
	mac.Write(wb[:])
	var out [8]byte
	copy(out[:], mac.Sum(nil))
	return out
}

type tagIndex struct {
	built int64
	byTag map[[8]byte]*benchUser
}

func buildTagIndex(users []benchUser, w int64) *tagIndex {
	idx := &tagIndex{built: w, byTag: make(map[[8]byte]*benchUser, len(users)*3)}
	for i := range users {
		for cand := w - authWindowTolerance; cand <= w+authWindowTolerance; cand++ {
			idx.byTag[windowTag(users[i].camoKey, cand)] = &users[i]
		}
	}
	return idx
}

func (idx *tagIndex) identify(tag [8]byte, token string, sessionID []byte) string {
	u, ok := idx.byTag[tag]
	if !ok {
		return ""
	}
	if !VerifyAuthToken(u.authKey, token, sessionID) {
		return ""
	}
	return u.id
}

type ecdhServer struct {
	priv   *ecdh.PrivateKey
	byHash map[[8]byte]*benchUser
}

func userHash(psk []byte) [8]byte {
	sum := sha256.Sum256(append([]byte("whispera-uid-v1"), psk...))
	var out [8]byte
	copy(out[:], sum[:])
	return out
}

func newECDHServer(users []benchUser) *ecdhServer {
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	s := &ecdhServer{priv: priv, byHash: make(map[[8]byte]*benchUser, len(users))}
	for i := range users {
		s.byHash[userHash(users[i].psk)] = &users[i]
	}
	return s
}

func selectorMask(shared []byte) [8]byte {
	sum := sha256.Sum256(append([]byte("whispera-sel-v1"), shared...))
	var out [8]byte
	copy(out[:], sum[:])
	return out
}

func clientSelector(serverPub *ecdh.PublicKey, ephPriv *ecdh.PrivateKey, psk []byte) [8]byte {
	shared, _ := ephPriv.ECDH(serverPub)
	mask := selectorMask(shared)
	uh := userHash(psk)
	var out [8]byte
	for i := range out {
		out[i] = uh[i] ^ mask[i]
	}
	return out
}

func (s *ecdhServer) identify(ephPub *ecdh.PublicKey, selector [8]byte, token string, sessionID []byte) string {
	shared, err := s.priv.ECDH(ephPub)
	if err != nil {
		return ""
	}
	mask := selectorMask(shared)
	var uh [8]byte
	for i := range uh {
		uh[i] = selector[i] ^ mask[i]
	}
	u, ok := s.byHash[uh]
	if !ok {
		return ""
	}
	if !VerifyAuthToken(u.authKey, token, sessionID) {
		return ""
	}
	return u.id
}

func BenchmarkIdentify(b *testing.B) {
	for _, n := range []int{1, 10, 100, 1000, 5000} {
		users := makeUsers(n)
		last := &users[n-1]
		w := window()

		sessionID := make([]byte, 16)
		rand.Read(sessionID)
		keyShare := make([]byte, 32)
		rand.Read(keyShare)
		token := AuthToken(last.authKey, w, sessionID)
		marker := camo.BuildMarker(last.camoKey, keyShare)

		b.Run(fmt.Sprintf("сейчас/линейно/users=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if currentIdentify(users, marker[:], keyShare, token, sessionID) == "" {
					b.Fatal("не опознан")
				}
			}
		})

		idx := buildTagIndex(users, w)
		tag := windowTag(last.camoKey, w)
		b.Run(fmt.Sprintf("А/оконная-метка/users=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if idx.identify(tag, token, sessionID) == "" {
					b.Fatal("не опознан")
				}
			}
		})

		srv := newECDHServer(users)
		ephPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
		sel := clientSelector(srv.priv.PublicKey(), ephPriv, last.psk)
		ephPub := ephPriv.PublicKey()
		b.Run(fmt.Sprintf("Б/ECDH-селектор/users=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if srv.identify(ephPub, sel, token, sessionID) == "" {
					b.Fatal("не опознан")
				}
			}
		})
	}
}

func BenchmarkIndexRebuild(b *testing.B) {
	for _, n := range []int{100, 1000, 5000} {
		users := makeUsers(n)
		w := window()
		b.Run(fmt.Sprintf("А/пересборка-окна/users=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				buildTagIndex(users, w)
			}
		})
		b.Run(fmt.Sprintf("Б/пересборка-при-смене-ключей/users=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				newECDHServer(users)
			}
		})
	}
}
