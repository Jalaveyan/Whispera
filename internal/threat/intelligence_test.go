package threat

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewIntelligenceEngine(t *testing.T) {
	ie := NewIntelligenceEngine()
	if ie == nil {
		t.Fatal("expected non-nil engine")
	}
	if ie.IndicatorCount() != 0 {
		t.Errorf("expected 0 indicators, got %d", ie.IndicatorCount())
	}
}

func TestAddIndicatorIP(t *testing.T) {
	ie := NewIntelligenceEngine()

	ie.AddIndicator(Indicator{
		Type:       ThreatBlockedIP,
		Value:      "1.2.3.4",
		Confidence: 0.9,
		Source:     "test",
	})

	if !ie.IsIPBlocked("1.2.3.4") {
		t.Error("expected IP to be blocked")
	}
	if ie.IsIPBlocked("5.6.7.8") {
		t.Error("expected IP to not be blocked")
	}
}

func TestAddIndicatorCIDR(t *testing.T) {
	ie := NewIntelligenceEngine()

	ie.AddIndicator(Indicator{
		Type:  ThreatBlockedCIDR,
		Value: "10.0.0.0/8",
	})

	if !ie.IsIPBlocked("10.1.2.3") {
		t.Error("expected 10.1.2.3 to be blocked by CIDR")
	}
	if ie.IsIPBlocked("192.168.1.1") {
		t.Error("expected 192.168.1.1 to not be blocked")
	}
}

func TestAddIndicatorASN(t *testing.T) {
	ie := NewIntelligenceEngine()

	ie.AddIndicator(Indicator{
		Type:  ThreatBlockedASN,
		Value: "AS12345",
	})

	if !ie.IsASNBlocked("AS12345") {
		t.Error("expected ASN to be blocked")
	}
	if ie.IsASNBlocked("AS99999") {
		t.Error("expected ASN to not be blocked")
	}
}

func TestCheckThreat(t *testing.T) {
	ie := NewIntelligenceEngine()

	ie.AddIndicator(Indicator{
		Type:        ThreatBlockedIP,
		Value:       "8.8.8.8",
		Description: "known DPI node",
	})

	threat := ie.CheckThreat("8.8.8.8")
	if threat == nil {
		t.Fatal("expected threat indicator")
	}
	if threat.Type != ThreatBlockedIP {
		t.Errorf("expected blocked_ip, got %s", threat.Type)
	}

	threat = ie.CheckThreat("1.1.1.1")
	if threat != nil {
		t.Error("expected no threat for clean IP")
	}
}

func TestGetReputation(t *testing.T) {
	ie := NewIntelligenceEngine()

	ie.AddIndicator(Indicator{
		Type:        ThreatBlockedIP,
		Value:       "6.6.6.6",
		Description: "malicious",
	})

	rep := ie.GetReputation("6.6.6.6")
	if rep.Score != 0.0 {
		t.Errorf("expected score 0.0, got %f", rep.Score)
	}
	if !rep.Blocked {
		t.Error("expected blocked")
	}

	rep = ie.GetReputation("9.9.9.9")
	if rep.Score != 1.0 {
		t.Errorf("expected score 1.0, got %f", rep.Score)
	}
	if rep.Blocked {
		t.Error("expected not blocked")
	}
}

func TestExportImport(t *testing.T) {
	ie := NewIntelligenceEngine()

	ie.AddIndicator(Indicator{
		Type:  ThreatBlockedIP,
		Value: "1.1.1.1",
	})
	ie.AddIndicator(Indicator{
		Type:  ThreatBlockedASN,
		Value: "AS111",
	})

	data, err := ie.Export()
	if err != nil {
		t.Fatalf("export error: %v", err)
	}

	ie2 := NewIntelligenceEngine()
	if err := ie2.Import(data); err != nil {
		t.Fatalf("import error: %v", err)
	}

	if !ie2.IsIPBlocked("1.1.1.1") {
		t.Error("imported engine should block 1.1.1.1")
	}
	if !ie2.IsASNBlocked("AS111") {
		t.Error("imported engine should block AS111")
	}
}

func TestFetchFeed(t *testing.T) {
	indicators := []Indicator{
		{Type: ThreatBlockedIP, Value: "10.0.0.1", Confidence: 0.95},
		{Type: ThreatBlockedIP, Value: "10.0.0.2", Confidence: 0.85},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(indicators)
	}))
	defer server.Close()

	ie := NewIntelligenceEngine()
	var updateCalled bool
	ie.OnUpdate(func(name string, count int) {
		updateCalled = true
		if count != 2 {
			t.Errorf("expected 2 indicators, got %d", count)
		}
	})

	var threatCount int
	ie.OnThreat(func(ind Indicator) {
		threatCount++
	})

	ie.AddFeed("test-feed", server.URL, "json", 1*time.Hour)
	ie.fetchFeed(ie.feeds[0])

	if !updateCalled {
		t.Error("update callback not called")
	}
	if threatCount != 2 {
		t.Errorf("expected 2 threat callbacks, got %d", threatCount)
	}
	if !ie.IsIPBlocked("10.0.0.1") {
		t.Error("expected 10.0.0.1 to be blocked after feed fetch")
	}
}

func TestGetSignatures(t *testing.T) {
	ie := NewIntelligenceEngine()

	ie.AddIndicator(Indicator{
		Type:  ThreatDPISignature,
		Value: "pattern-xyz",
	})
	ie.AddIndicator(Indicator{
		Type:  ThreatFingerprint,
		Value: "ja3-abc",
	})

	sigs := ie.GetSignatures()
	if len(sigs) != 2 {
		t.Errorf("expected 2 signatures, got %d", len(sigs))
	}
}

func TestAddFeed(t *testing.T) {
	ie := NewIntelligenceEngine()
	ie.AddFeed("rkn", "https://example.com/feed.json", "json", 30*time.Minute)

	feeds := ie.GetFeeds()
	if len(feeds) != 1 {
		t.Fatalf("expected 1 feed, got %d", len(feeds))
	}
	if feeds[0].Name != "rkn" {
		t.Errorf("expected feed name 'rkn', got %s", feeds[0].Name)
	}
	if feeds[0].Interval != 30*time.Minute {
		t.Errorf("expected 30m interval, got %v", feeds[0].Interval)
	}
}
