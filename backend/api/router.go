package api

import (
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/Nciibi/seagles/auth"
	"github.com/Nciibi/seagles/config"
	"github.com/Nciibi/seagles/kev"
	dbpkg "github.com/Nciibi/seagles/db"
	"github.com/Nciibi/seagles/middleware"
	"github.com/Nciibi/seagles/slog"
)

func success(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, gin.H{"data": data, "error": nil})
}

func fail(c *gin.Context, status int, msg string) {
	c.JSON(status, gin.H{"data": nil, "error": msg})
}

type HealthStatus struct {
	Status  string `json:"status"`
	Service string `json:"service"`
	Version string `json:"version"`
	DBOK    bool   `json:"db_ok"`
	RedisOK bool   `json:"redis_ok"`
	MinIOOK bool   `json:"minio_ok"`
	FAOK    bool   `json:"fa_ok"`
}

func NewRouter(db *sql.DB, cfg *config.Config, kevCatalog *kev.KEVCatalog) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	r.Use(gin.Recovery())

	rl := middleware.NewRateLimiter(cfg.RateLimitPerMin, 1*time.Minute)

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
		origin := c.Request.Header.Get("Origin")
		allowedOrigin := ""
		for _, o := range cfg.AllowedOrigins {
			if o == origin {
				allowedOrigin = o
				break
			}
		}
		if allowedOrigin != "" {
			c.Header("Access-Control-Allow-Origin", allowedOrigin)
		}
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

	r.Use(middleware.RateLimitMiddleware(rl))
	r.Use(middleware.MetricsMiddleware())
	r.Use(middleware.SanitizeInput(middleware.DefaultXSSConfig))
	r.Use(middleware.AuditLogger(db, "/api/v1/auth/login", "/api/v1/auth/refresh", "/api/v1/health", "/api/v1/ws"))

	v1 := r.Group("/api/v1")
	{
		v1.POST("/auth/login", auth.LoginHandler(db))
		v1.POST("/auth/refresh", auth.RefreshTokenHandler(db))

		v1.GET("/metrics", middleware.MetricsHandler())
		v1.GET("/swagger.json", SwaggerJSONHandler())
		v1.GET("/docs", SwaggerUIHandler())

		v1.GET("/health", func(c *gin.Context) {
			dbOk := dbpkg.IsHealthy()
			allOk := true
			if !dbOk {
				allOk = false
			}

			hs := HealthStatus{
				Status:  "ok",
				Service: "ironmesh-api",
				Version: "2.1.0",
				DBOK:    dbOk,
				RedisOK: cfg.RedisURL == "",
				MinIOOK: cfg.S3Endpoint == "",
				FAOK:    cfg.FirmwareAnalyzerURL == "",
			}

			if cfg.RedisURL != "" {
				hs.RedisOK = middleware.CheckRedis(cfg.RedisURL)
				if !hs.RedisOK {
					allOk = false
				}
			}
			if cfg.S3Endpoint != "" {
				hs.MinIOOK = middleware.CheckMinIO(cfg.S3Endpoint)
				if !hs.MinIOOK {
					allOk = false
				}
			}
			if cfg.FirmwareAnalyzerURL != "" {
				hs.FAOK = middleware.CheckFirmwareAnalyzer(cfg.FirmwareAnalyzerURL)
				if !hs.FAOK {
					allOk = false
				}
			}

			if !allOk {
				hs.Status = "degraded"
			}

			statusCode := http.StatusOK
			if !dbOk {
				statusCode = http.StatusServiceUnavailable
			}
			c.JSON(statusCode, hs)
		})

		protected := v1.Group("")
		protected.GET("/ws", WSHandler(cfg.AllowedOrigins))
		protected.Use(auth.AuthMiddleware())
		{
			protected.GET("/auth/me", auth.MeHandler())
			protected.GET("/auth/permissions", auth.PermissionsHandler())
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
			protected.GET("/audit-log", auth.RequireRole("auditor"), middleware.ListAuditLogsHandler(db))
			protected.GET("/sessions", auth.AdminOnly(), ListSessionsHandler(db))
			protected.DELETE("/sessions/:id", auth.AdminOnly(), RevokeSessionHandler(db))
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
