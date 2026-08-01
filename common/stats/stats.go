package stats

import (
	"github.com/nekoskin/whispera/common/log"
	"sync"
	"sync/atomic"
	"time"
)

type TrafficStats struct {
	mu sync.RWMutex

	totalBytesRx   atomic.Int64
	totalBytesTx   atomic.Int64
	totalPacketsRx atomic.Int64
	totalPacketsTx atomic.Int64

	userStats map[string]*UserStats

	historySize int
	history     []TrafficSnapshot

	startTime time.Time

	log *logger.Logger
}

type UserStats struct {
	UserID       string    `json:"user_id"`
	BytesRx      int64     `json:"bytes_rx"`
	BytesTx      int64     `json:"bytes_tx"`
	PacketsRx    int64     `json:"packets_rx"`
	PacketsTx    int64     `json:"packets_tx"`
	LastActivity time.Time `json:"last_activity"`
	SessionCount int       `json:"session_count"`
	AssignedIP   string    `json:"assigned_ip,omitempty"`
}

type TrafficSnapshot struct {
	Timestamp time.Time `json:"timestamp"`
	BytesRx   int64     `json:"bytes_rx"`
	BytesTx   int64     `json:"bytes_tx"`
	PacketsRx int64     `json:"packets_rx"`
	PacketsTx int64     `json:"packets_tx"`
	UserCount int       `json:"user_count"`
}

func New() *TrafficStats {
	return &TrafficStats{
		userStats:   make(map[string]*UserStats),
		historySize: 168,
		history:     make([]TrafficSnapshot, 0, 168),
		startTime:   time.Now(),
		log:         logger.Module("stats"),
	}
}

func (s *TrafficStats) AddRx(userID string, bytes int64) {
	s.totalBytesRx.Add(bytes)
	s.totalPacketsRx.Add(1)

	if userID != "" {
		s.mu.Lock()
		user := s.getOrCreateUser(userID)
		user.BytesRx += bytes
		user.PacketsRx++
		user.LastActivity = time.Now()
		s.mu.Unlock()
	}
}

func (s *TrafficStats) AddTx(userID string, bytes int64) {
	s.totalBytesTx.Add(bytes)
	s.totalPacketsTx.Add(1)

	if userID != "" {
		s.mu.Lock()
		user := s.getOrCreateUser(userID)
		user.BytesTx += bytes
		user.PacketsTx++
		user.LastActivity = time.Now()
		s.mu.Unlock()
	}
}

func (s *TrafficStats) SetUserIP(userID, ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	user := s.getOrCreateUser(userID)
	user.AssignedIP = ip
}

func (s *TrafficStats) IncrementSessionCount(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	user := s.getOrCreateUser(userID)
	user.SessionCount++
}

func (s *TrafficStats) DecrementSessionCount(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if user, ok := s.userStats[userID]; ok {
		user.SessionCount--
		if user.SessionCount < 0 {
			user.SessionCount = 0
		}
	}
}

func (s *TrafficStats) getOrCreateUser(userID string) *UserStats {
	if user, ok := s.userStats[userID]; ok {
		return user
	}

	user := &UserStats{
		UserID:       userID,
		LastActivity: time.Now(),
	}
	s.userStats[userID] = user
	return user
}

func (s *TrafficStats) TakeSnapshot() {
	s.mu.Lock()
	defer s.mu.Unlock()

	snapshot := TrafficSnapshot{
		Timestamp: time.Now(),
		BytesRx:   s.totalBytesRx.Load(),
		BytesTx:   s.totalBytesTx.Load(),
		PacketsRx: s.totalPacketsRx.Load(),
		PacketsTx: s.totalPacketsTx.Load(),
		UserCount: len(s.userStats),
	}

	s.history = append(s.history, snapshot)

	if len(s.history) > s.historySize {
		s.history = s.history[len(s.history)-s.historySize:]
	}
}

var (
	globalStats     *TrafficStats
	globalStatsOnce sync.Once
)

func Global() *TrafficStats {
	globalStatsOnce.Do(func() {
		globalStats = New()
		go func() {
			ticker := time.NewTicker(1 * time.Hour)
			defer ticker.Stop()
			for range ticker.C {
				globalStats.TakeSnapshot()
			}
		}()
	})
	return globalStats
}

func AddRx(userID string, bytes int64) {
	Global().AddRx(userID, bytes)
}

func AddTx(userID string, bytes int64) {
	Global().AddTx(userID, bytes)
}
