package update

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func (u *Updater) Apply(info VersionInfo) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	tmpFile, err := u.download(info.URL)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer os.Remove(tmpFile)

	if err := u.verifyChecksum(tmpFile, info.Checksum); err != nil {
		return fmt.Errorf("checksum: %w", err)
	}

	if u.config.PublicKey != nil && info.Signature != "" {
		if err := u.verifySignature(tmpFile, info.Signature); err != nil {
			return fmt.Errorf("signature: %w", err)
		}
	}

	if err := u.backup(); err != nil {
		return fmt.Errorf("backup: %w", err)
	}

	if err := u.atomicReplace(tmpFile); err != nil {
		u.rollback()
		return fmt.Errorf("replace: %w", err)
	}

	if u.onUpdateApplied != nil {
		u.onUpdateApplied(u.config.CurrentVersion, info.Version)
	}
	u.config.CurrentVersion = info.Version

	return nil
}

func (u *Updater) backup() error {
	os.MkdirAll(u.config.BackupDir, 0755)
	src := u.config.BinaryPath
	dst := filepath.Join(u.config.BackupDir, fmt.Sprintf("whispera-%s.bak", u.config.CurrentVersion))

	srcFile, err := os.Open(src)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

func (u *Updater) atomicReplace(tmpFile string) error {
	info, err := os.Stat(u.config.BinaryPath)
	if err == nil {
		os.Chmod(tmpFile, info.Mode())
	} else {
		os.Chmod(tmpFile, 0755)
	}

	return os.Rename(tmpFile, u.config.BinaryPath)
}

func (u *Updater) rollback() error {
	pattern := filepath.Join(u.config.BackupDir, "whispera-*.bak")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return fmt.Errorf("no backup found")
	}

	latest := matches[len(matches)-1]
	return os.Rename(latest, u.config.BinaryPath)
}
