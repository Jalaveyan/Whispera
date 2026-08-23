package protocol

import (
	"net"
	"sync"
	"time"

	"github.com/nekoskin/whispera/core/protocol/camo"
)

const selectorIndexTTL = time.Second

type selectorEntry struct {
	userID  string
	psk     []byte
	camoKey []byte
}

type selectorIndex struct {
	mu       sync.RWMutex
	builtAt  time.Time
	builtVer uint64
	hasVer   bool
	byTag    map[[camo.SelectorSize]byte]selectorEntry
	keys     [][]byte
}

func (s *selectorIndex) camoKeys(cfg *ServerConfig) [][]byte {
	s.snapshot(cfg)
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.keys
}

func (s *selectorIndex) snapshot(cfg *ServerConfig) map[[camo.SelectorSize]byte]selectorEntry {
	var ver uint64
	versioned := cfg.UsersVersion != nil
	if versioned {
		ver = cfg.UsersVersion()
	}

	s.mu.RLock()
	idx := s.byTag
	fresh := idx != nil
	if fresh {
		if versioned && s.hasVer {
			fresh = s.builtVer == ver
		} else {
			fresh = time.Since(s.builtAt) < selectorIndexTTL
		}
	}
	s.mu.RUnlock()
	if fresh {
		return idx
	}

	built := make(map[[camo.SelectorSize]byte]selectorEntry)
	if len(cfg.SharedSecret) == 32 {
		built[camo.UserTag(cfg.SharedSecret)] = selectorEntry{
			userID:  "default",
			psk:     cfg.SharedSecret,
			camoKey: camo.DeriveKey(cfg.SharedSecret),
		}
	}
	if cfg.GetUsers != nil {
		for _, u := range cfg.GetUsers() {
			if len(u.PSK) != 32 {
				continue
			}
			built[camo.UserTag(u.PSK)] = selectorEntry{
				userID:  u.UserID,
				psk:     u.PSK,
				camoKey: camo.DeriveKey(u.PSK),
			}
		}
	}
	keys := make([][]byte, 0, len(built))
	for _, e := range built {
		keys = append(keys, e.camoKey)
	}

	s.mu.Lock()
	s.byTag = built
	s.keys = keys
	s.builtAt = time.Now()
	s.builtVer, s.hasVer = ver, versioned
	s.mu.Unlock()
	return built
}

func resolveBySelector(cfg *ServerConfig, random, keyShare []byte) (selectorEntry, bool) {
	var none selectorEntry
	if len(random) != 32 || len(keyShare) != 32 {
		return none, false
	}
	id := activeCertIdentity()
	if id == nil {
		return none, false
	}
	priv, err := id.SelectorKey()
	if err != nil {
		return none, false
	}
	sel, marker, ok := camo.SplitRandom(random)
	if !ok {
		return none, false
	}
	tag, err := camo.OpenSelector(sel, priv, keyShare)
	if err != nil {
		return none, false
	}
	entry, found := cfg.selectors.snapshot(cfg)[tag]
	if !found {
		return none, false
	}
	if !camo.MarkerMatchesKey(entry.camoKey, marker, keyShare, time.Now().Unix()) {
		return none, false
	}
	return entry, true
}

type knownUser struct {
	id  string
	psk []byte
}

func knownUserOf(c net.Conn) knownUser {
	raw := NetConnOf(c)
	if raw == nil {
		raw = c
	}
	if pc, ok := raw.(*prefixConn); ok && len(pc.knownPSK) == 32 {
		return knownUser{id: pc.knownUser, psk: pc.knownPSK}
	}
	return knownUser{}
}

func resolveSecretFor(cfg *ServerConfig, known knownUser, token string, sessionID []byte) ([]byte, string) {
	if len(known.psk) == 32 {
		if VerifyAuthToken(DeriveKeys(known.psk).Auth, token, sessionID) {
			return known.psk, known.id
		}
	}
	return resolveSecret(cfg, token, sessionID)
}
