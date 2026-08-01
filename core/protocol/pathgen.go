package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"time"
)

const authWindowSeconds = 30

const authWindowTolerance = 1

const clockDriftProbeWindows = 10

func AuthToken(authKey []byte, window int64, sessionID []byte) string {
	mac := hmac.New(sha256.New, authKey)
	var wb [8]byte
	binary.BigEndian.PutUint64(wb[:], uint64(window))
	mac.Write(wb[:])
	mac.Write(sessionID)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func ClientAuthToken(authKey, sessionID []byte) string {
	return AuthToken(authKey, time.Now().Unix()/authWindowSeconds, sessionID)
}

func VerifyAuthToken(authKey []byte, token string, sessionID []byte) bool {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		return false
	}
	w := time.Now().Unix() / authWindowSeconds
	for candidate := w - authWindowTolerance; candidate <= w+authWindowTolerance; candidate++ {
		if macMatches(authKey, candidate, sessionID, raw) {
			return true
		}
	}
	return false
}

func macMatches(authKey []byte, window int64, sessionID, want []byte) bool {
	mac := hmac.New(sha256.New, authKey)
	var wb [8]byte
	binary.BigEndian.PutUint64(wb[:], uint64(window))
	mac.Write(wb[:])
	mac.Write(sessionID)
	return hmac.Equal(mac.Sum(nil), want)
}

func ProbeClockDrift(authKey []byte, token string, sessionID []byte) (driftWindows int64, found bool) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		return 0, false
	}
	w := time.Now().Unix() / authWindowSeconds
	for offset := int64(authWindowTolerance + 1); offset <= clockDriftProbeWindows; offset++ {
		if macMatches(authKey, w+offset, sessionID, raw) {
			return offset, true
		}
		if macMatches(authKey, w-offset, sessionID, raw) {
			return -offset, true
		}
	}
	return 0, false
}
