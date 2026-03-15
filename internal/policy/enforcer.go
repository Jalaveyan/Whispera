package policy

import (
	"sync"
	"time"

	"whispera/internal/logger"
)

type BandwidthEnforcer struct {
	userStats map[string]*UserBandwidthStats
	mu        sync.RWMutex
	policyMgr *PolicyManager
	log       *logger.Logger
}

type UserBandwidthStats struct {
	UploadBytes   int64
	DownloadBytes int64
	LastReset     time.Time
	mu            sync.RWMutex
}

func NewBandwidthEnforcer(policyMgr *PolicyManager) *BandwidthEnforcer {
	be := &BandwidthEnforcer{
		userStats: make(map[string]*UserBandwidthStats),
		policyMgr: policyMgr,
		log:       logger.Module("policy"),
	}

	go be.cleanupLoop()

	return be
}

func (be *BandwidthEnforcer) RecordUpload(userID string, bytes int64) bool {
	be.mu.Lock()
	stats, exists := be.userStats[userID]
	if !exists {
		stats = &UserBandwidthStats{
			LastReset: time.Now(),
		}
		be.userStats[userID] = stats
	}
	be.mu.Unlock()

	stats.mu.Lock()
	stats.UploadBytes += bytes
	uploadBytes := stats.UploadBytes
	stats.mu.Unlock()

	policy := be.policyMgr.GetPolicy(userID)
	if policy == nil {
		return true
	}

	uploadAllowed, _, uploadRemaining, _ := policy.CheckBandwidthLimit(uploadBytes, 0)
	if !uploadAllowed || uploadRemaining == 0 {
		be.log.Warn("User %s exceeded upload limit: %d bytes", userID, uploadBytes)
		return false
	}

	return true
}

func (be *BandwidthEnforcer) RecordDownload(userID string, bytes int64) bool {
	be.mu.Lock()
	stats, exists := be.userStats[userID]
	if !exists {
		stats = &UserBandwidthStats{
			LastReset: time.Now(),
		}
		be.userStats[userID] = stats
	}
	be.mu.Unlock()

	stats.mu.Lock()
	stats.DownloadBytes += bytes
	downloadBytes := stats.DownloadBytes
	stats.mu.Unlock()

	policy := be.policyMgr.GetPolicy(userID)
	if policy == nil {
		return true
	}

	_, downloadAllowed, _, downloadRemaining := policy.CheckBandwidthLimit(0, downloadBytes)
	if !downloadAllowed || downloadRemaining == 0 {
		be.log.Warn("User %s exceeded download limit: %d bytes", userID, downloadBytes)
		return false
	}

	return true
}

func (be *BandwidthEnforcer) GetStats(userID string) (uploadBytes, downloadBytes int64) {
	be.mu.RLock()
	stats, exists := be.userStats[userID]
	be.mu.RUnlock()

	if !exists {
		return 0, 0
	}

	stats.mu.RLock()
	defer stats.mu.RUnlock()
	return stats.UploadBytes, stats.DownloadBytes
}

func (be *BandwidthEnforcer) ResetStats(userID string) {
	be.mu.Lock()
	defer be.mu.Unlock()

	if stats, exists := be.userStats[userID]; exists {
		stats.mu.Lock()
		stats.UploadBytes = 0
		stats.DownloadBytes = 0
		stats.LastReset = time.Now()
		stats.mu.Unlock()
	}
}

func (be *BandwidthEnforcer) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		be.mu.Lock()
		now := time.Now()
		for userID, stats := range be.userStats {
			stats.mu.RLock()
			lastReset := stats.LastReset
			stats.mu.RUnlock()

			if now.Sub(lastReset) > 24*time.Hour {
				delete(be.userStats, userID)
			}
		}
		be.mu.Unlock()
	}
}

type ConnectionEnforcer struct {
	userConnections map[string]int
	ipConnections   map[string]int
	mu              sync.RWMutex
	policyMgr       *PolicyManager
	log             *logger.Logger
}

func NewConnectionEnforcer(policyMgr *PolicyManager) *ConnectionEnforcer {
	return &ConnectionEnforcer{
		userConnections: make(map[string]int),
		ipConnections:   make(map[string]int),
		policyMgr:       policyMgr,
		log:             logger.Module("policy"),
	}
}

func (ce *ConnectionEnforcer) CheckConnection(userID, ipAddr string) bool {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	policy := ce.policyMgr.GetPolicy(userID)
	if policy == nil {
		return true
	}

	currentUserConnections := ce.userConnections[userID]
	if !policy.CheckConnectionLimit(currentUserConnections) {
		ce.log.Warn("User %s exceeded connection limit: %d connections", userID, currentUserConnections)
		return false
	}

	if policy.MaxConnectionsPerIP > 0 {
		currentIPConnections := ce.ipConnections[ipAddr]
		if currentIPConnections >= policy.MaxConnectionsPerIP {
			ce.log.Warn("IP %s exceeded connection limit: %d connections", ipAddr, currentIPConnections)
			return false
		}
	}

	return true
}

func (ce *ConnectionEnforcer) AddConnection(userID, ipAddr string) {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	ce.userConnections[userID]++
	if ipAddr != "" {
		ce.ipConnections[ipAddr]++
	}
}

func (ce *ConnectionEnforcer) RemoveConnection(userID, ipAddr string) {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	if ce.userConnections[userID] > 0 {
		ce.userConnections[userID]--
		if ce.userConnections[userID] == 0 {
			delete(ce.userConnections, userID)
		}
	}

	if ipAddr != "" && ce.ipConnections[ipAddr] > 0 {
		ce.ipConnections[ipAddr]--
		if ce.ipConnections[ipAddr] == 0 {
			delete(ce.ipConnections, ipAddr)
		}
	}
}

func (ce *ConnectionEnforcer) GetConnectionCount(userID string) int {
	ce.mu.RLock()
	defer ce.mu.RUnlock()
	return ce.userConnections[userID]
}

type TimeBasedEnforcer struct {
	policyMgr *PolicyManager
}

func NewTimeBasedEnforcer(policyMgr *PolicyManager) *TimeBasedEnforcer {
	return &TimeBasedEnforcer{
		policyMgr: policyMgr,
	}
}

func (tbe *TimeBasedEnforcer) CheckTimeBasedPolicy(userID string, now time.Time) bool {
	policy := tbe.policyMgr.GetPolicy(userID)
	if policy == nil {
		return true
	}

	return policy.CheckTimeBasedPolicy(now)
}
