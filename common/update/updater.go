package update

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

type VersionInfo struct {
	Version   string `json:"version"`
	Channel   string `json:"channel"`
	Checksum  string `json:"checksum_sha256"`
	Signature string `json:"signature_ed25519"`
	URL       string `json:"url"`
	Size      int64  `json:"size"`
	ReleaseAt string `json:"released_at"`
	Changelog string `json:"changelog,omitempty"`
}

type Manifest struct {
	Latest   VersionInfo            `json:"latest"`
	Versions map[string]VersionInfo `json:"versions"`
}

type Config struct {
	ManifestURL    string
	PublicKey      ed25519.PublicKey
	CurrentVersion string
	BinaryPath     string
	BackupDir      string
	CheckInterval  time.Duration
}

type Updater struct {
	config *Config
	client *http.Client
	mu     sync.Mutex
	stopCh chan struct{}

	onUpdateAvailable func(VersionInfo)
	onUpdateApplied   func(string, string)
	onUpdateFailed    func(string, error)
}

func NewUpdater(cfg *Config) *Updater {
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = 1 * time.Hour
	}
	if cfg.BackupDir == "" {
		cfg.BackupDir = "/etc/whispera/backups"
	}
	return &Updater{
		config: cfg,
		client: &http.Client{Timeout: 60 * time.Second},
		stopCh: make(chan struct{}),
	}
}

func (u *Updater) Start() {
	go func() {
		ticker := time.NewTicker(u.config.CheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-u.stopCh:
				return
			case <-ticker.C:
				u.CheckAndApply()
			}
		}
	}()
}

func (u *Updater) Stop() {
	close(u.stopCh)
}

func (u *Updater) CheckForUpdate() (*VersionInfo, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u.config.ManifestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("manifest HTTP %d", resp.StatusCode)
	}

	var manifest Manifest
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&manifest); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}

	if manifest.Latest.Version == u.config.CurrentVersion {
		return nil, nil
	}

	return &manifest.Latest, nil
}

func (u *Updater) CheckAndApply() {
	info, err := u.CheckForUpdate()
	if err != nil {
		if u.onUpdateFailed != nil {
			u.onUpdateFailed("", err)
		}
		return
	}
	if info == nil {
		return
	}

	if u.onUpdateAvailable != nil {
		u.onUpdateAvailable(*info)
	}

	if err := u.Apply(*info); err != nil {
		if u.onUpdateFailed != nil {
			u.onUpdateFailed(info.Version, err)
		}
	}
}
