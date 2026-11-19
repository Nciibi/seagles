package cache

import (
	"testing"
	"time"
)

func TestNewTokenBlacklist(t *testing.T) {
	b := NewTokenBlacklist()
	if b == nil {
		t.Fatal("expected non-nil blacklist")
	}
	if b.Len() != 0 {
		t.Fatalf("expected empty blacklist, got %d", b.Len())
	}
}

func TestAddAndIsBlacklisted(t *testing.T) {
	b := NewTokenBlacklist()
	b.Add("token1")
	b.Add("token2")

	if !b.IsBlacklisted("token1") {
		t.Fatal("expected token1 to be blacklisted")
	}
	if !b.IsBlacklisted("token2") {
		t.Fatal("expected token2 to be blacklisted")
	}
	if b.IsBlacklisted("token3") {
		t.Fatal("expected token3 to NOT be blacklisted")
	}
}

func TestRemove(t *testing.T) {
	b := NewTokenBlacklist()
	b.Add("token1")
	b.Remove("token1")
	if b.IsBlacklisted("token1") {
		t.Fatal("expected token1 to be removed from blacklist")
	}
}

func TestLen(t *testing.T) {
	b := NewTokenBlacklist()
	if b.Len() != 0 {
		t.Fatalf("expected 0, got %d", b.Len())
	}
	b.Add("a")
	if b.Len() != 1 {
		t.Fatalf("expected 1, got %d", b.Len())
	}
	b.Add("b")
	if b.Len() != 2 {
		t.Fatalf("expected 2, got %d", b.Len())
	}
	b.Remove("a")
	if b.Len() != 1 {
		t.Fatalf("expected 1 after remove, got %d", b.Len())
	}
}

func TestGlobalBlacklist(t *testing.T) {
	if IsTokenBlacklisted("nonexistent") {
		t.Fatal("expected nonexistent to not be blacklisted")
	}
	BlacklistToken("test-jti")
	if !IsTokenBlacklisted("test-jti") {
		t.Fatal("expected test-jti to be blacklisted")
	}
}

func TestRedisBlacklistFallsBackWhenUnavailable(t *testing.T) {
	CloseRedisBlacklist()
	t.Cleanup(CloseRedisBlacklist)

	// Invalid URL and unreachable server must both leave the process-local
	// blacklist fully functional rather than failing startup or token checks.
	InitRedisBlacklist("://not-a-url", time.Minute)
	if currentRedisClient() != nil {
		t.Fatal("invalid REDIS_URL must not install a Redis client")
	}

	InitRedisBlacklist("redis://127.0.0.1:1", time.Minute)
	if currentRedisClient() != nil {
		t.Fatal("unreachable Redis must not install a client")
	}

	BlacklistToken("fallback-jti")
	if !IsTokenBlacklisted("fallback-jti") {
		t.Fatal("local revocation must still work without Redis")
	}
}

func TestConcurrentAccess(t *testing.T) {
	b := NewTokenBlacklist()
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(n int) {
			token := string(rune('0' + n))
			b.Add(token)
			b.IsBlacklisted(token)
			b.Remove(token)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}
