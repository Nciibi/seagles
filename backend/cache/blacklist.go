package cache

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Nciibi/seagles/slog"
)

type blacklistEntry struct {
	addedAt time.Time
}

type TokenBlacklist struct {
	mu      sync.RWMutex
	entries map[string]blacklistEntry
	maxTTL  time.Duration
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

const revokedKeyPrefix = "seagles:revoked:"

var (
	redisMu       sync.RWMutex
	redisClient   *redis.Client
	revokedTTL    = 15 * time.Minute
	redisCallTimeout = 2 * time.Second
)

// InitRedisBlacklist configures token revocation to use Redis when it is
// reachable. Without this, an in-memory map is used, which is only correct for
// a single process: with N replicas, logging out on one pod leaves the access
// token valid on the other N-1 until it expires.
//
// A malformed URL or an unreachable server is a warning, not a startup failure:
// single-instance deployments legitimately run without Redis. The local map
// still protects the current process in that case.
func InitRedisBlacklist(redisURL string, ttl time.Duration) {
	if strings.TrimSpace(redisURL) == "" {
		return
	}
	if ttl > 0 {
		revokedTTL = ttl
	}

	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		slog.Warn("REDIS_URL is invalid; token revocation stays process-local", "error", err.Error())
		return
	}
	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		slog.Warn("Redis unavailable; token revocation stays process-local", "error", err.Error())
		return
	}

	redisMu.Lock()
	redisClient = client
	redisMu.Unlock()
	slog.Info("Token revocation backed by Redis", "ttl", revokedTTL.String())
}

// CloseRedisBlacklist releases the Redis connection at shutdown.
func CloseRedisBlacklist() {
	redisMu.Lock()
	defer redisMu.Unlock()
	if redisClient != nil {
		_ = redisClient.Close()
		redisClient = nil
	}
}

func currentRedisClient() *redis.Client {
	redisMu.RLock()
	defer redisMu.RUnlock()
	return redisClient
}

func IsTokenBlacklisted(jti string) bool {
	if globalBlacklist.IsBlacklisted(jti) {
		return true
	}
	client := currentRedisClient()
	if client == nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), redisCallTimeout)
	defer cancel()
	found, err := client.Exists(ctx, revokedKeyPrefix+jti).Result()
	if err != nil {
		// Fail open on a transient Redis error: the token's signature and expiry
		// are still verified, and the alternative (rejecting on any Redis blip)
		// would turn a cache outage into a site-wide authentication outage.
		slog.Warn("Redis blacklist lookup failed", "error", err.Error())
		return false
	}
	if found > 0 {
		// Warm the local map so subsequent checks on this replica skip Redis.
		globalBlacklist.Add(jti)
		return true
	}
	return false
}

func BlacklistToken(jti string) {
	globalBlacklist.Add(jti)
	client := currentRedisClient()
	if client == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), redisCallTimeout)
	defer cancel()
	if err := client.Set(ctx, revokedKeyPrefix+jti, "1", revokedTTL).Err(); err != nil {
		slog.Error("Redis token revocation failed", "error", err.Error())
	}
}
