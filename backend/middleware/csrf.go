package middleware

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type csrfStore struct {
	mu       sync.RWMutex
	tokens   map[string]time.Time
	maxAge   time.Duration
}

var globalCSRF = &csrfStore{
	tokens: make(map[string]time.Time),
	maxAge: 24 * time.Hour,
}

func generateCSRFToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func SetCSRFToken(c *gin.Context) {
	token := generateCSRFToken()
	hash := hashToken(token)

	globalCSRF.mu.Lock()
	globalCSRF.tokens[hash] = time.Now().Add(globalCSRF.maxAge)
	globalCSRF.mu.Unlock()

	c.Header("X-CSRF-Token", token)
}

func ValidateCSRFToken(token string) bool {
	hash := hashToken(token)

	globalCSRF.mu.Lock()
	defer globalCSRF.mu.Unlock()

	expiry, exists := globalCSRF.tokens[hash]
	if !exists {
		return false
	}
	if time.Now().After(expiry) {
		delete(globalCSRF.tokens, hash)
		return false
	}

	delete(globalCSRF.tokens, hash)
	return true
}

func CSRFMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Requests carrying a Bearer token are not susceptible to classic CSRF:
		// browsers never attach Authorization headers automatically, so a
		// cross-site attacker cannot forge them. Enforcing single-use CSRF
		// tokens on these requests would break every token-authenticated
		// write without adding security.
		if strings.HasPrefix(c.GetHeader("Authorization"), "Bearer ") {
			SetCSRFToken(c)
			c.Next()
			return
		}

		if c.Request.Method == "GET" || c.Request.Method == "HEAD" || c.Request.Method == "OPTIONS" {
			SetCSRFToken(c)
			c.Next()
			return
		}

		token := c.GetHeader("X-CSRF-Token")
		if token == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"data": nil, "error": "CSRF token required",
			})
			return
		}

		if !ValidateCSRFToken(token) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"data": nil, "error": "Invalid or expired CSRF token",
			})
			return
		}

		SetCSRFToken(c)
		c.Next()
	}
}

// purgeExpiredCSRFTokens periodically removes expired tokens. Without this,
// tokens minted by GET requests (and never submitted) would accumulate forever.
func purgeExpiredCSRFTokens() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		globalCSRF.mu.Lock()
		for hash, expiry := range globalCSRF.tokens {
			if now.After(expiry) {
				delete(globalCSRF.tokens, hash)
			}
		}
		globalCSRF.mu.Unlock()
	}
}

func init() {
	go purgeExpiredCSRFTokens()
}
