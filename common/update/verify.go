package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const defaultMaxBinarySize = 200 * 1024 * 1024 // 200MB safety cap when manifest doesn't specify a size

func (u *Updater) download(url string, maxSize int64) (string, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	if maxSize <= 0 {
		maxSize = defaultMaxBinarySize
	}

	// Create the temp file next to the target binary so the final os.Rename
	// in atomicReplace stays on the same filesystem (cross-device renames fail).
	tmpDir := filepath.Dir(u.config.BinaryPath)
	tmpFile, err := os.CreateTemp(tmpDir, "whispera-update-*")
	if err != nil {
		tmpFile, err = os.CreateTemp("", "whispera-update-*")
		if err != nil {
			return "", err
		}
	}

	limited := io.LimitReader(resp.Body, maxSize+1)
	n, err := io.Copy(tmpFile, limited)
	if err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", err
	}
	if n > maxSize {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("update payload exceeds size limit (%d bytes)", maxSize)
	}
	tmpFile.Close()
	return tmpFile.Name(), nil
}

func (u *Updater) verifyChecksum(file, expectedHex string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}

	actual := hex.EncodeToString(h.Sum(nil))
	if actual != expectedHex {
		return fmt.Errorf("checksum mismatch: got %s, expected %s", actual, expectedHex)
	}
	return nil
}

func (u *Updater) verifySignature(file, sigHex string) error {
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	digest := h.Sum(nil)

	if !ed25519.Verify(u.config.PublicKey, digest, sig) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}
