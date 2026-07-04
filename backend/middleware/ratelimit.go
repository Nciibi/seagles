package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type visitor struct {
	count    int
	lastSeen time.Time
}

type RateLimitRule struct {
	Path   string
	Method string
	Limit  int
	Window time.Duration
}

type RateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	default  *RateLimitRule
	rules    []RateLimitRule
}

func NewRateLimiter(defaultLimit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		default:  &RateLimitRule{Limit: defaultLimit, Window: window},
	}
	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) AddRule(method, path string, limit int, window time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.rules = append(rl.rules, RateLimitRule{
		Method: method,
		Path:   path,
		Limit:  limit,
		Window: window,
	})
}

func (rl *RateLimiter) getRule(method, path string) *RateLimitRule {
	for _, rule := range rl.rules {
		if rule.Method == method && matchPath(rule.Path, path) {
			return &rule
		}
	}
	return rl.default
}

func matchPath(pattern, path string) bool {
	if pattern == path {
		return true
	}
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		return len(path) >= len(pattern)-1 && path[:len(pattern)-1] == pattern[:len(pattern)-1]
	}
	return false
}

func (rl *RateLimiter) key(ip, userID string) string {
	if userID != "" {
		return "user:" + userID
	}
	return "ip:" + ip
}

func (rl *RateLimiter) Allow(ip, userID, method, path string) (bool, int, int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	key := rl.key(ip, userID)
	rule := rl.getRule(method, path)

	v, exists := rl.visitors[key]
	now := time.Now()

	if !exists || now.Sub(v.lastSeen) > rule.Window {
		rl.visitors[key] = &visitor{count: 1, lastSeen: now}
		return true, rule.Limit - 1, rule.Limit
	}

	v.count++
	v.lastSeen = now
	remaining := rule.Limit - v.count
	if remaining < 0 {
		remaining = 0
	}
	return v.count <= rule.Limit, remaining, rule.Limit
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for k, v := range rl.visitors {
			if now.Sub(v.lastSeen) > rl.default.Window {
				delete(rl.visitors, k)
			}
		}
		rl.mu.Unlock()
	}
}

func RateLimitMiddleware(rl *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		userID, _ := c.Get("user_id")
		userIDStr, _ := userID.(string)

		allowed, remaining, limit := rl.Allow(clientIP, userIDStr, c.Request.Method, c.Request.URL.Path)

		c.Header("X-RateLimit-Limit", itoa(limit))
		c.Header("X-RateLimit-Remaining", itoa(remaining))
		c.Header("X-RateLimit-Reset", itoa(int(time.Now().Add(30 * time.Second).Unix())))

		if !allowed {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"data": nil, "error": "Rate limit exceeded. Try again later.",
			})
			return
		}
		c.Next()
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	if neg {
		s = "-" + s
	}
	return s
}
