package cache

import (
	"sync"
	"time"
)

type blacklistEntry struct {
	addedAt time.Time
}

type TokenBlacklist struct {
	mu       sync.RWMutex
	entries  map[string]blacklistEntry
	maxTTL   time.Duration
}

func NewTokenBlacklist() *TokenBlacklist {
	b := &TokenBlacklist{
		entries: make(map[string]blacklistEntry),
		maxTTL:  24 * time.Hour,
	}
	go b.cleanup()
	return b
}

func (b *TokenBlacklist) Add(jti string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries[jti] = blacklistEntry{addedAt: time.Now()}
}

func (b *TokenBlacklist) IsBlacklisted(jti string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, exists := b.entries[jti]
	return exists
}

func (b *TokenBlacklist) Remove(jti string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.entries, jti)
}

func (b *TokenBlacklist) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.entries)
}

func (b *TokenBlacklist) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		b.mu.Lock()
		cutoff := time.Now().Add(-b.maxTTL)
		for jti, entry := range b.entries {
			if entry.addedAt.Before(cutoff) {
				delete(b.entries, jti)
			}
		}
		b.mu.Unlock()
	}
}

var globalBlacklist = NewTokenBlacklist()

func IsTokenBlacklisted(jti string) bool {
	return globalBlacklist.IsBlacklisted(jti)
}

func BlacklistToken(jti string) {
	globalBlacklist.Add(jti)
}
