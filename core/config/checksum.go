package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/nekoskin/whispera/common/fsown"
	"os"
	"path/filepath"
)

var integrityKey = func() string {
	if key := os.Getenv("WHISPERA_INTEGRITY_KEY"); key != "" {
		return key
	}
	return "DEVELOPMENT-ONLY-REPLACE-IN-PRODUCTION"
}()

const checksumFile = ".config.checksum"

func (p *Provider) CalculateChecksum() (string, error) {
	if p.configPath == "" {
		return "", fmt.Errorf("config path is empty")
	}

	data, err := os.ReadFile(p.configPath)
	if err != nil {
		return "", err
	}

	h := hmac.New(sha256.New, []byte(integrityKey))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (p *Provider) UpdateChecksum() error {
	sum, err := p.CalculateChecksum()
	if err != nil {
		return err
	}

	dir := filepath.Dir(p.configPath)
	checksumPath := filepath.Join(dir, checksumFile)

	return fsown.WriteFile(checksumPath, []byte(sum), 0644)
}

func (p *Provider) VerifyIntegrity() error {
	if _, err := os.Stat(p.configPath); os.IsNotExist(err) {
		return nil
	}

	dir := filepath.Dir(p.configPath)
	checksumPath := filepath.Join(dir, checksumFile)

	savedSumBytes, err := os.ReadFile(checksumPath)
	if os.IsNotExist(err) {
		return p.UpdateChecksum()
	} else if err != nil {
		return fmt.Errorf("failed to read checksum file: %w", err)
	}

	currentSum, err := p.CalculateChecksum()
	if err != nil {
		return fmt.Errorf("failed to calculate current checksum: %w", err)
	}

	savedSum := string(savedSumBytes)

	if currentSum != savedSum {
		return fmt.Errorf("INTEGRITY_VIOLATION: Config checksum mismatch! Expected %s, got %s", savedSum, currentSum)
	}

	return nil
}

func (p *Provider) AlertAndDie(reason string) {
	fmt.Printf("CRITICAL SECURITY ALERT: %s\n", reason)
	os.Exit(1)
}
