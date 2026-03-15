package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

func GenerateSecret() (string, error) {
	randomBytes := make([]byte, 20)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes), nil
}

func GenerateQRCodeURL(issuer, user, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		issuer, user, secret, issuer)
}

func ValidateCode(secret, code string, skew int) (bool, error) {
	secret = strings.TrimSpace(strings.ToUpper(secret))
	secret = strings.ReplaceAll(secret, " ", "")
	secret = strings.ReplaceAll(secret, "-", "")

	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		key, err = base32.StdEncoding.DecodeString(secret)
		if err != nil {
			return false, fmt.Errorf("invalid secret format: %v", err)
		}
	}

	now := time.Now().Unix()
	step := int64(30)
	currentInterval := now / step

	for i := -skew; i <= skew; i++ {
		interval := currentInterval + int64(i)
		generatedCode := generateTOTP(key, interval)
		if generatedCode == code {
			return true, nil
		}
	}

	return false, nil
}

func generateTOTP(key []byte, interval int64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(interval))

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	codeInt := binary.BigEndian.Uint32(sum[offset : offset+4])
	codeInt &= 0x7fffffff
	codeInt %= 1000000

	return fmt.Sprintf("%06d", codeInt)
}
