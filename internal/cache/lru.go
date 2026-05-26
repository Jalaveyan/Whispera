package cache

import (
	"context"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

const defaultLRUCapacity = 10000

type lruEntry struct {
	value     []byte
	counter   int64
	expiresAt time.Time
}

type LRUCache struct {
	c  *lru.Cache[string, *lruEntry]
	mu sync.Mutex
}

func NewLRUCache(capacity int) *LRUCache {
	if capacity <= 0 {
		capacity = defaultLRUCapacity
	}
	c, _ := lru.New[string, *lruEntry](capacity)
	return &LRUCache{c: c}
}

func (m *LRUCache) Get(_ context.Context, key string) ([]byte, error) {
	e, ok := m.c.Get(key)
	if !ok {
		return nil, nil
	}
	if !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
		m.c.Remove(key)
		return nil, nil
	}
	return e.value, nil
}

func (m *LRUCache) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	e := &lruEntry{value: value}
	if ttl > 0 {
		e.expiresAt = time.Now().Add(ttl)
	}
	m.c.Add(key, e)
	return nil
}

func (m *LRUCache) Delete(_ context.Context, key string) error {
	m.c.Remove(key)
	return nil
}

func (m *LRUCache) Exists(_ context.Context, key string) bool {
	e, ok := m.c.Get(key)
	if !ok {
		return false
	}
	if !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
		m.c.Remove(key)
		return false
	}
	return true
}

func (m *LRUCache) Incr(_ context.Context, key string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.c.Get(key)
	if !ok || (!e.expiresAt.IsZero() && time.Now().After(e.expiresAt)) {
		e = &lruEntry{}
		m.c.Add(key, e)
	}
	e.counter++
	return e.counter, nil
}

func (m *LRUCache) IncrWithTTL(_ context.Context, key string, ttl time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.c.Get(key)
	if !ok || (!e.expiresAt.IsZero() && time.Now().After(e.expiresAt)) {
		e = &lruEntry{}
		if ttl > 0 {
			e.expiresAt = time.Now().Add(ttl)
		}
		m.c.Add(key, e)
	}
	e.counter++
	return e.counter, nil
}

func (m *LRUCache) Close() error { return nil }

func (m *LRUCache) Ping(_ context.Context) error { return nil }

func (m *LRUCache) Type() string { return "lru" }
