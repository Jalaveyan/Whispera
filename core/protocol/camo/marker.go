package camo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"time"

	utls "github.com/refraction-networking/utls"
)

const (
	WindowSeconds = 30
	WindowTol     = 1

	driftProbeWindows = 10
)

func DeriveKey(psk []byte) []byte {
	if len(psk) != 32 {
		return nil
	}
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte("whispera-camo-v1"))
	return mac.Sum(nil)
}

func ExtractX25519KeyShare(shares []utls.KeyShare) []byte {
	for _, ks := range shares {
		if ks.Group == utls.X25519 {
			return ks.Data
		}
	}
	return nil
}

func markerForWindow(key []byte, window int64, keyShare []byte) [32]byte {
	var out [32]byte
	mac := hmac.New(sha256.New, key)
	var wb [8]byte
	binary.BigEndian.PutUint64(wb[:], uint64(window))
	mac.Write(wb[:])
	mac.Write(keyShare)
	copy(out[:], mac.Sum(nil))
	return out
}

func BuildMarker(key []byte, keyShare []byte) [32]byte {
	return markerForWindow(key, time.Now().Unix()/WindowSeconds, keyShare)
}

func MarkerMatches(keys [][]byte, random []byte, keyShare []byte) bool {
	if len(random) != 32 || len(keys) == 0 || len(keyShare) == 0 {
		return false
	}
	w := time.Now().Unix() / WindowSeconds
	for _, key := range keys {
		if len(key) == 0 {
			continue
		}
		for cand := w - WindowTol; cand <= w+WindowTol; cand++ {
			marker := markerForWindow(key, cand, keyShare)
			if hmac.Equal(marker[:], random) {
				return true
			}
		}
	}
	return false
}

func MarkerDrift(keys [][]byte, random []byte, keyShare []byte) (driftWindows int64, found bool) {
	if len(random) != 32 || len(keys) == 0 || len(keyShare) == 0 {
		return 0, false
	}
	w := time.Now().Unix() / WindowSeconds
	for _, key := range keys {
		if len(key) == 0 {
			continue
		}
		for offset := int64(WindowTol + 1); offset <= driftProbeWindows; offset++ {
			if up := markerForWindow(key, w+offset, keyShare); hmac.Equal(up[:], random) {
				return offset, true
			}
			if down := markerForWindow(key, w-offset, keyShare); hmac.Equal(down[:], random) {
				return -offset, true
			}
		}
	}
	return 0, false
}
