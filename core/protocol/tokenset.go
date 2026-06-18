package protocol

import (
	"hash/fnv"
	"sync"
)

const tokenSeenShardCount = 16
const tokenSeenShardCleanupThreshold = 1000 / tokenSeenShardCount

type tokenSeenShard struct {
	mu   sync.Mutex
	seen map[string]int64
}

type tokenSeenSet struct {
	once   sync.Once
	shards [tokenSeenShardCount]tokenSeenShard
}

func (s *tokenSeenSet) init() {
	s.once.Do(func() {
		for i := range s.shards {
			s.shards[i].seen = make(map[string]int64)
		}
	})
}

func tokenShardIndex(token string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(token))
	return h.Sum32() % tokenSeenShardCount
}

func (s *tokenSeenSet) consume(token string, now int64) bool {
	s.init()
	shard := &s.shards[tokenShardIndex(token)]

	shard.mu.Lock()
	defer shard.mu.Unlock()

	if t, ok := shard.seen[token]; ok && now-t < replayWindowSeconds {
		return false
	}
	shard.seen[token] = now
	if len(shard.seen) > tokenSeenShardCleanupThreshold {
		for k, t := range shard.seen {
			if now-t >= replayWindowSeconds {
				delete(shard.seen, k)
			}
		}
	}
	return true
}

func (s *tokenSeenSet) sweep(now int64) {
	s.init()
	for i := range s.shards {
		shard := &s.shards[i]
		shard.mu.Lock()
		for k, t := range shard.seen {
			if now-t >= replayWindowSeconds {
				delete(shard.seen, k)
			}
		}
		shard.mu.Unlock()
	}
}
