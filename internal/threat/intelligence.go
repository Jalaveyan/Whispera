package threat

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

type ThreatType string

const (
	ThreatBlockedIP    ThreatType = "blocked_ip"
	ThreatBlockedCIDR  ThreatType = "blocked_cidr"
	ThreatBlockedASN   ThreatType = "blocked_asn"
	ThreatDPISignature ThreatType = "dpi_signature"
	ThreatFingerprint  ThreatType = "fingerprint"
	ThreatBlockedDomain ThreatType = "blocked_domain"
)

type Indicator struct {
	Type        ThreatType `json:"type"`
	Value       string     `json:"value"`
	Confidence  float64    `json:"confidence"`
	Source      string     `json:"source"`
	FirstSeen   time.Time  `json:"first_seen"`
	LastSeen    time.Time  `json:"last_seen"`
	Description string     `json:"description,omitempty"`
	Region      string     `json:"region,omitempty"`
	Tags        []string   `json:"tags,omitempty"`
}

type Feed struct {
	Name        string      `json:"name"`
	URL         string      `json:"url"`
	Format      string      `json:"format"`
	Interval    time.Duration `json:"interval"`
	LastFetch   time.Time   `json:"last_fetch"`
	Indicators  int         `json:"indicator_count"`
}

type IntelligenceEngine struct {
	mu          sync.RWMutex
	feeds       []*Feed
	indicators  map[string][]Indicator
	blockedIPs  map[string]bool
	blockedCIDR []*net.IPNet
	blockedASN  map[string]bool
	signatures  map[string]Indicator

	client     *http.Client
	stopCh     chan struct{}
	onThreat   func(Indicator)
	onUpdate   func(feedName string, count int)
}

func NewIntelligenceEngine() *IntelligenceEngine {
	return &IntelligenceEngine{
		indicators:  make(map[string][]Indicator),
		blockedIPs:  make(map[string]bool),
		blockedASN:  make(map[string]bool),
		signatures:  make(map[string]Indicator),
		client:      &http.Client{Timeout: 30 * time.Second},
		stopCh:      make(chan struct{}),
	}
}

func (ie *IntelligenceEngine) OnThreat(fn func(Indicator))              { ie.onThreat = fn }
func (ie *IntelligenceEngine) OnUpdate(fn func(string, int))            { ie.onUpdate = fn }

func (ie *IntelligenceEngine) AddFeed(name, url, format string, interval time.Duration) {
	ie.mu.Lock()
	defer ie.mu.Unlock()

	if interval <= 0 {
		interval = 1 * time.Hour
	}

	ie.feeds = append(ie.feeds, &Feed{
		Name:     name,
		URL:      url,
		Format:   format,
		Interval: interval,
	})
}

func (ie *IntelligenceEngine) AddIndicator(ind Indicator) {
	ie.mu.Lock()
	defer ie.mu.Unlock()

	key := string(ind.Type) + ":" + ind.Value
	ie.indicators[key] = append(ie.indicators[key], ind)

	switch ind.Type {
	case ThreatBlockedIP:
		ie.blockedIPs[ind.Value] = true
	case ThreatBlockedCIDR:
		_, cidr, err := net.ParseCIDR(ind.Value)
		if err == nil {
			ie.blockedCIDR = append(ie.blockedCIDR, cidr)
		}
	case ThreatBlockedASN:
		ie.blockedASN[ind.Value] = true
	case ThreatDPISignature, ThreatFingerprint:
		ie.signatures[ind.Value] = ind
	default:
	}
}

func (ie *IntelligenceEngine) IsIPBlocked(ip string) bool {
	ie.mu.RLock()
	defer ie.mu.RUnlock()

	if ie.blockedIPs[ip] {
		return true
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range ie.blockedCIDR {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

func (ie *IntelligenceEngine) IsASNBlocked(asn string) bool {
	ie.mu.RLock()
	defer ie.mu.RUnlock()
	return ie.blockedASN[asn]
}

func (ie *IntelligenceEngine) GetSignatures() []Indicator {
	ie.mu.RLock()
	defer ie.mu.RUnlock()

	sigs := make([]Indicator, 0, len(ie.signatures))
	for _, s := range ie.signatures {
		sigs = append(sigs, s)
	}
	return sigs
}

func (ie *IntelligenceEngine) CheckThreat(ip string) *Indicator {
	ie.mu.RLock()
	defer ie.mu.RUnlock()

	if ie.blockedIPs[ip] {
		key := string(ThreatBlockedIP) + ":" + ip
		if inds, ok := ie.indicators[key]; ok && len(inds) > 0 {
			ind := inds[len(inds)-1]
			return &ind
		}
		return &Indicator{Type: ThreatBlockedIP, Value: ip}
	}

	parsed := net.ParseIP(ip)
	if parsed != nil {
		for _, cidr := range ie.blockedCIDR {
			if cidr.Contains(parsed) {
				return &Indicator{
					Type:  ThreatBlockedCIDR,
					Value: cidr.String(),
				}
			}
		}
	}

	return nil
}

func (ie *IntelligenceEngine) Start() {
	for _, feed := range ie.feeds {
		go ie.fetchLoop(feed)
	}
}

func (ie *IntelligenceEngine) Stop() {
	close(ie.stopCh)
}

func (ie *IntelligenceEngine) fetchLoop(feed *Feed) {
	ie.fetchFeed(feed)

	ticker := time.NewTicker(feed.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ie.stopCh:
			return
		case <-ticker.C:
			ie.fetchFeed(feed)
		}
	}
}

func (ie *IntelligenceEngine) fetchFeed(feed *Feed) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, feed.URL, nil)
	if err != nil {
		return
	}
	resp, err := ie.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	var indicators []Indicator
	switch feed.Format {
	case "json":
		if err := json.NewDecoder(resp.Body).Decode(&indicators); err != nil {
			return
		}
	default:
		return
	}

	count := 0
	for _, ind := range indicators {
		ind.Source = feed.Name
		if ind.FirstSeen.IsZero() {
			ind.FirstSeen = time.Now()
		}
		ind.LastSeen = time.Now()

		ie.AddIndicator(ind)
		count++

		if ie.onThreat != nil && ind.Confidence >= 0.8 {
			ie.onThreat(ind)
		}
	}

	ie.mu.Lock()
	feed.LastFetch = time.Now()
	feed.Indicators = count
	ie.mu.Unlock()

	if ie.onUpdate != nil {
		ie.onUpdate(feed.Name, count)
	}
}

func (ie *IntelligenceEngine) GetFeeds() []Feed {
	ie.mu.RLock()
	defer ie.mu.RUnlock()

	feeds := make([]Feed, len(ie.feeds))
	for i, f := range ie.feeds {
		feeds[i] = *f
	}
	return feeds
}

func (ie *IntelligenceEngine) IndicatorCount() int {
	ie.mu.RLock()
	defer ie.mu.RUnlock()
	return len(ie.indicators)
}

func (ie *IntelligenceEngine) Export() ([]byte, error) {
	ie.mu.RLock()
	defer ie.mu.RUnlock()

	var all []Indicator
	for _, inds := range ie.indicators {
		all = append(all, inds...)
	}
	return json.Marshal(all)
}

func (ie *IntelligenceEngine) Import(data []byte) error {
	var indicators []Indicator
	if err := json.Unmarshal(data, &indicators); err != nil {
		return fmt.Errorf("invalid indicator data: %w", err)
	}
	for _, ind := range indicators {
		ie.AddIndicator(ind)
	}
	return nil
}

type ReputationScore struct {
	IP         string  `json:"ip"`
	Score      float64 `json:"score"`
	Category   string  `json:"category"`
	Blocked    bool    `json:"blocked"`
	Reasons    []string `json:"reasons"`
}

func (ie *IntelligenceEngine) GetReputation(ip string) ReputationScore {
	score := ReputationScore{
		IP:    ip,
		Score: 1.0,
	}

	if threat := ie.CheckThreat(ip); threat != nil {
		score.Score = 0.0
		score.Blocked = true
		score.Category = string(threat.Type)
		score.Reasons = append(score.Reasons, threat.Description)
		if threat.Description == "" {
			score.Reasons = []string{fmt.Sprintf("matched %s: %s", threat.Type, threat.Value)}
		}
	}

	return score
}
