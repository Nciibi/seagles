package api

import (
	"database/sql"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/yourusername/seagles/auth"
	"github.com/yourusername/seagles/config"
	"github.com/yourusername/seagles/kev"
	"github.com/yourusername/seagles/slog"
)

type rateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	limit    int
	window   time.Duration
}

type visitor struct {
	count    int
	lastSeen time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		visitors: make(map[string]*visitor),
		limit:    limit,
		window:   window,
	}
	go rl.cleanup()
	return rl
}

func (rl *rateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for k, v := range rl.visitors {
			if now.Sub(v.lastSeen) > rl.window {
				delete(rl.visitors, k)
			}
		}
		rl.mu.Unlock()
	}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[key]
	now := time.Now()

	if !exists || now.Sub(v.lastSeen) > rl.window {
		rl.visitors[key] = &visitor{count: 1, lastSeen: now}
		return true
	}

	v.count++
	v.lastSeen = now
	return v.count <= rl.limit
}

func success(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, gin.H{"data": data, "error": nil})
}

func fail(c *gin.Context, status int, msg string) {
	c.JSON(status, gin.H{"data": nil, "error": msg})
}

func NewRouter(db *sql.DB, cfg *config.Config, kevCatalog *kev.KEVCatalog) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	r.Use(gin.Recovery())

	rl := newRateLimiter(cfg.RateLimitPerMin, 1*time.Minute)

	r.Use(func(c *gin.Context) {
		start := time.Now()

		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.NewString()
		}
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)

		c.Next()

		status := c.Writer.Status()
		latency := time.Since(start)
		slog.Debug("request",
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", status,
			"latency", latency.String(),
			"request_id", requestID,
		)
	})

	r.Use(func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Header("Content-Security-Policy", "default-src 'self'")
		c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		c.Next()
	})

	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID, X-CSRF-Token")
		c.Header("Access-Control-Max-Age", "86400")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	})

	r.Use(func(c *gin.Context) {
		bodySize := c.Request.ContentLength
		if bodySize > 100<<20 {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
				"data": nil, "error": "Request body too large (max 100MB)",
			})
			return
		}
		c.Next()
	})

	r.Use(func(c *gin.Context) {
		clientIP := c.ClientIP()
		if !rl.allow(clientIP) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"data": nil, "error": "Rate limit exceeded. Try again later.",
			})
			return
		}
		c.Next()
	})

	v1 := r.Group("/api/v1")
	{
		v1.POST("/auth/login", auth.LoginHandler(db))
		v1.POST("/auth/refresh", auth.RefreshTokenHandler(db))

		v1.GET("/health", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"status":  "ok",
				"service": "ironmesh-api",
				"version": "2.1.0",
				"db_ok":   db.Stats().OpenConnections > 0,
			})
		})

		v1.GET("/ws", WSHandler())

		protected := v1.Group("")
		protected.Use(auth.AuthMiddleware())
		{
			protected.GET("/auth/me", auth.MeHandler())
			protected.POST("/auth/logout", auth.LogoutHandler())
			protected.POST("/auth/change-password", auth.ChangePasswordHandler(db))
			protected.GET("/stats", StatsHandler(db))
			protected.GET("/devices", ListDevicesHandler(db))
			protected.GET("/devices/:id", GetDeviceHandler(db))
			protected.DELETE("/devices/:id", auth.AdminOnly(), DeleteDeviceHandler(db))
			protected.POST("/devices/:id/scan", auth.AdminOnly(), TriggerDeviceScanHandler(db, cfg, kevCatalog))
			protected.GET("/devices/:id/risk-breakdown", RiskBreakdownHandler(db))
			protected.GET("/scans", ListScansHandler(db))
			protected.GET("/scans/:id", GetScanHandler(db))
			protected.POST("/scan/network", auth.AdminOnly(), NetworkScanHandler(db, cfg))
			protected.GET("/vulnerabilities", ListVulnerabilitiesHandler(db))
			protected.PATCH("/vulnerabilities/:id/resolve", auth.AdminOnly(), ResolveVulnerabilityHandler(db))
			protected.GET("/firmware", ListFirmwareHandler(db))
			protected.POST("/firmware/:id/analyze", auth.AdminOnly(), AnalyzeFirmwareHandler(db, cfg))
			protected.POST("/firmware/upload", auth.AdminOnly(), UploadFirmwareHandler(db, cfg))
			protected.GET("/alerts", ListAlertsHandler(db))
			protected.POST("/alerts/:id/ack", AckAlertHandler(db))
			protected.GET("/kev/status", KEVStatusHandler(kevCatalog))
			protected.GET("/safelists", ListSafelistHandler(db))
			protected.POST("/safelists", auth.AdminOnly(), CreateSafelistHandler(db))
			protected.DELETE("/safelists/:id", auth.AdminOnly(), DeleteSafelistHandler(db))
			protected.GET("/scan-profiles", ListScanProfilesHandler(db))
			protected.GET("/scan-scopes", ListScanScopesHandler(db))
			protected.POST("/scan-scopes", auth.AdminOnly(), CreateScanScopeHandler(db))
			protected.DELETE("/scan-scopes/:id", auth.AdminOnly(), DeleteScanScopeHandler(db))
			protected.GET("/webhooks", auth.AdminOnly(), ListWebhooksHandler(db))
			protected.POST("/webhooks", auth.AdminOnly(), CreateWebhookHandler(db))
			protected.DELETE("/webhooks/:id", auth.AdminOnly(), DeleteWebhookHandler(db))
			protected.POST("/webhooks/:id/test", auth.AdminOnly(), TestWebhookHandler(db))
			protected.GET("/users", auth.AdminOnly(), auth.ListUsersHandler(db))
			protected.POST("/users", auth.AdminOnly(), auth.RegisterHandler(db))
		}
	}

	return r
}

func nullableString(s string) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return &s
}
