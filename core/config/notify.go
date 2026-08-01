package config

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	telegramAPI = "https://api.telegram.org/bot%s/sendMessage"
	hostName    = "Whispera Server"
)

type NotificationConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Token   string `yaml:"token" json:"token"`
	ChatID  string `yaml:"chat_id" json:"chat_id"`
}

func (p *Provider) SendNotification(message string) error {
	p.mu.RLock()
	cfg := p.config.Notifications
	p.mu.RUnlock()

	if !cfg.Enabled || cfg.Token == "" || cfg.ChatID == "" {
		return nil
	}

	fullMsg := fmt.Sprintf("🔒 *%s*\n\n%s\n\n🕒 %s", hostName, message, time.Now().Format(time.RFC1123))

	apiURL := fmt.Sprintf(telegramAPI, cfg.Token)
	vals := url.Values{
		"chat_id":    {cfg.ChatID},
		"text":       {fullMsg},
		"parse_mode": {"Markdown"},
	}
	postReq, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, apiURL, strings.NewReader(vals.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(postReq)

	if err != nil {
		return fmt.Errorf("failed to send telegram notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram api error: %s", string(body))
	}

	return nil
}
