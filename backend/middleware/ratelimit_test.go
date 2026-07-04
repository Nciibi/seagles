package middleware

import (
	"testing"
	"time"
)

func TestNewRateLimiter(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute)
	if rl == nil {
		t.Fatal("expected non-nil rate limiter")
	}
	if rl.fallback.Limit != 10 {
		t.Fatalf("expected limit 10, got %d", rl.fallback.Limit)
	}
}

func TestRateLimiter_Allow_WithinLimit(t *testing.T) {
	rl := NewRateLimiter(5, time.Minute)
	for i := 0; i < 5; i++ {
		allowed, remaining, limit := rl.Allow("192.168.1.1", "", "GET", "/test")
		if !allowed {
			t.Fatalf("iter %d: expected allowed", i)
		}
		if remaining != 5-i-1 {
			t.Fatalf("iter %d: expected remaining %d, got %d", i, 5-i-1, remaining)
		}
		if limit != 5 {
			t.Fatalf("iter %d: expected limit 5, got %d", i, limit)
		}
	}
}

func TestRateLimiter_Allow_ExceedsLimit(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		rl.Allow("192.168.1.1", "", "GET", "/test")
	}
	allowed, remaining, _ := rl.Allow("192.168.1.1", "", "GET", "/test")
	if allowed {
		t.Fatal("expected rate limited")
	}
	if remaining != 0 {
		t.Fatalf("expected remaining 0, got %d", remaining)
	}
}

func TestRateLimiter_DifferentIPs(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)
	rl.Allow("192.168.1.1", "", "GET", "/test")
	rl.Allow("192.168.1.1", "", "GET", "/test")

	allowed, _, _ := rl.Allow("192.168.1.1", "", "GET", "/test")
	if allowed {
		t.Fatal("expected 192.168.1.1 to be rate limited (3rd call, limit=2)")
	}

	allowed2, _, _ := rl.Allow("192.168.1.2", "", "GET", "/test")
	if !allowed2 {
		t.Fatal("expected 192.168.1.2 to NOT be rate limited (first call)")
	}
}

func TestRateLimiter_WindowReset(t *testing.T) {
	rl := NewRateLimiter(1, 50*time.Millisecond)
	rl.Allow("192.168.1.1", "", "GET", "/test")

	_, remaining, _ := rl.Allow("192.168.1.1", "", "GET", "/test")
	if remaining != 0 {
		t.Fatalf("expected remaining 0 before window reset, got %d", remaining)
	}

	time.Sleep(60 * time.Millisecond)

	allowed, remaining, _ := rl.Allow("192.168.1.1", "", "GET", "/test")
	if !allowed {
		t.Fatal("expected allowed after window reset")
	}
	if remaining != 0 {
		t.Fatalf("expected remaining 0 after reset, got %d", remaining)
	}
}

func TestRateLimiter_UserKey(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		rl.Allow("", "user-1", "GET", "/test")
	}
	allowed, _, _ := rl.Allow("", "user-1", "GET", "/test")
	if allowed {
		t.Fatal("expected user-1 to be rate limited")
	}

	allowed2, _, _ := rl.Allow("", "user-2", "GET", "/test")
	if !allowed2 {
		t.Fatal("expected user-2 to NOT be rate limited")
	}
}

func TestRateLimiter_AddRule(t *testing.T) {
	rl := NewRateLimiter(5, time.Minute)
	rl.AddRule("POST", "/api/v1/auth/login", 2, time.Minute)

	for i := 0; i < 2; i++ {
		allowed, _, _ := rl.Allow("192.168.1.1", "", "POST", "/api/v1/auth/login")
		if !allowed {
			t.Fatalf("iter %d: expected allowed", i)
		}
	}

	allowed, _, _ := rl.Allow("192.168.1.1", "", "POST", "/api/v1/auth/login")
	if allowed {
		t.Fatal("expected rate limited by custom rule")
	}

	allowed2, _, _ := rl.Allow("192.168.1.1", "", "GET", "/other")
	if !allowed2 {
		t.Fatal("expected different endpoint to use default limit")
	}
}

func TestMatchPath(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		match   bool
	}{
		{"/api/v1/devices", "/api/v1/devices", true},
		{"/api/v1/devices", "/api/v1/scan", false},
		{"/api/v1/devices/*", "/api/v1/devices/123", true},
		{"/api/v1/devices/*", "/api/v1/devices/123/scan", true},
		{"/api/v1/devices/*", "/api/v1/devices", false},
	}

	for _, tt := range tests {
		result := matchPath(tt.pattern, tt.path)
		if result != tt.match {
			t.Errorf("matchPath(%q, %q) = %v, want %v", tt.pattern, tt.path, result, tt.match)
		}
	}
}

func TestItoa(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "0"},
		{1, "1"},
		{100, "100"},
		{-5, "-5"},
	}

	for _, tt := range tests {
		result := itoa(tt.input)
		if result != tt.want {
			t.Errorf("itoa(%d) = %s, want %s", tt.input, result, tt.want)
		}
	}
}
