package crypto

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"io"

	xchacha "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type DirectionalKeys struct {
	Key   []byte
	Salt4 [4]byte
}

type AEADState struct {
	sendAEAD cipher.AEAD
	recvAEAD cipher.AEAD
	sendSalt [4]byte
	recvSalt [4]byte
}

func DeriveDirectionalKeys(psk []byte, isClient bool) (send, recv DirectionalKeys, err error) {
	info := []byte("whispera v1 data-keys")
	r := hkdf.New(sha256.New, psk, nil, info)
	material := make([]byte, 72)
	if _, err = io.ReadFull(r, material); err != nil {
		return
	}
	aKey := material[0:32]
	aSalt := material[32:36]
	bKey := material[36:68]
	bSalt := material[68:72]

	if isClient {
		copy(send.Salt4[:], aSalt)
		send.Key = append([]byte(nil), aKey...)
		copy(recv.Salt4[:], bSalt)
		recv.Key = append([]byte(nil), bKey...)
	} else {
		copy(send.Salt4[:], bSalt)
		send.Key = append([]byte(nil), bKey...)
		copy(recv.Salt4[:], aSalt)
		recv.Key = append([]byte(nil), aKey...)
	}
	return
}

func NewAEADState(send, recv DirectionalKeys) (*AEADState, error) {
	aSend, err := xchacha.New(send.Key)
	if err != nil {
		return nil, err
	}
	aRecv, err := xchacha.New(recv.Key)
	if err != nil {
		return nil, err
	}
	s := &AEADState{sendAEAD: aSend, recvAEAD: aRecv}
	s.sendSalt = send.Salt4
	s.recvSalt = recv.Salt4
	return s, nil
}

func buildNonce(salt4 [4]byte, seq uint32) (nonce [12]byte) {
	copy(nonce[0:4], salt4[:])

	nonce[4] = 0
	nonce[5] = 0
	nonce[6] = 0
	nonce[7] = 0
	nonce[8] = byte(seq >> 24)
	nonce[9] = byte(seq >> 16)
	nonce[10] = byte(seq >> 8)
	nonce[11] = byte(seq)
	return
}

func (s *AEADState) Encrypt(seq uint32, aad, plaintext []byte) ([]byte, error) {
	nonce := buildNonce(s.sendSalt, seq)
	return s.sendAEAD.Seal(plaintext[:0], nonce[:], plaintext, aad), nil
}

func (s *AEADState) Decrypt(seq uint32, aad, ciphertext []byte) ([]byte, error) {
	nonce := buildNonce(s.recvSalt, seq)
	out, err := s.recvAEAD.Open(ciphertext[:0], nonce[:], ciphertext, aad)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func EqualPSK(a, b []byte) bool {
	mac := hmac.New(sha256.New, []byte("psk-ct"))
	mac.Write(a)
	sumA := mac.Sum(nil)
	mac.Reset()
	mac.Write(b)
	sumB := mac.Sum(nil)
	if len(sumA) != len(sumB) {
		return false
	}
	var v byte
	for i := range sumA {
		v |= sumA[i] ^ sumB[i]
	}
	return v == 0
}
