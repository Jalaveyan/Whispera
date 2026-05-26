package cache

import (
	"log"
)


func New(redisURL string) Cache {
	if redisURL == "" {
		log.Println("[CACHE] Using in-memory LRU cache (no Redis URL configured)")
		return NewLRUCache(0)
	}

	rc, err := NewRedisCache(redisURL)
	if err != nil {
		log.Printf("[CACHE] Redis unavailable (%v), falling back to in-memory LRU cache", err)
		return NewLRUCache(0)
	}

	log.Printf("[CACHE] Connected to Redis at %s", redisURL)
	return rc
}

var globalCache Cache

func SetGlobal(c Cache) {
	globalCache = c
}

func Global() Cache {
	if globalCache == nil {
		globalCache = NewLRUCache(0)
	}
	return globalCache
}
