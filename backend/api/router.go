package api

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/seagles/auth"
	"github.com/yourusername/seagles/config"
	"github.com/yourusername/seagles/kev"
)

// success sends a standardized success response.
func success(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, gin.H{"data": data, "error": nil})
}

// fail sends a standardized error response.
func fail(c *gin.Context, status int, msg string) {
	c.JSON(status, gin.H{"data": nil, "error": msg})
}

// NewRouter creates and configures the Gin router with all API routes.
func NewRouter(db *sql.DB, cfg *config.Config, kevCatalog *kev.KEVCatalog) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	r := gin.Default()

	// Security headers middleware
	r.Use(func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Next()
	})

	// CORS middleware
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	})

	// Request ID middleware
	r.Use(func(c *gin.Context) {
		c.Set("request_id", c.GetHeader("X-Request-ID"))
		c.Next()
	})

	v1 := r.Group("/api/v1")
	{
		// Public routes (no auth required)
		v1.POST("/auth/login", auth.LoginHandler(db))

		// Health check (public)
		v1.GET("/health", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok", "service": "ironmesh-api", "version": "2.0.0"})
		})

		// Protected routes (auth required)
		protected := v1.Group("")
		protected.Use(auth.AuthMiddleware())
		{
			// Auth
			protected.GET("/auth/me", auth.MeHandler())

			// Stats
			protected.GET("/stats", StatsHandler(db))

			// Devices
			protected.GET("/devices", ListDevicesHandler(db))
			protected.GET("/devices/:id", GetDeviceHandler(db))
			protected.DELETE("/devices/:id", auth.AdminOnly(), DeleteDeviceHandler(db))
			protected.POST("/devices/:id/scan", auth.AdminOnly(), TriggerDeviceScanHandler(db, cfg, kevCatalog))
			protected.GET("/devices/:id/risk-breakdown", RiskBreakdownHandler(db))

			// Scans
			protected.GET("/scans", ListScansHandler(db))
			protected.GET("/scans/:id", GetScanHandler(db))
			protected.POST("/scan/network", auth.AdminOnly(), NetworkScanHandler(db, cfg))

			// Vulnerabilities
			protected.GET("/vulnerabilities", ListVulnerabilitiesHandler(db))
			protected.PATCH("/vulnerabilities/:id/resolve", auth.AdminOnly(), ResolveVulnerabilityHandler(db))

			// Firmware
			protected.GET("/firmware", ListFirmwareHandler(db))
			protected.POST("/firmware/:id/analyze", auth.AdminOnly(), AnalyzeFirmwareHandler(db, cfg))
			protected.POST("/firmware/upload", auth.AdminOnly(), UploadFirmwareHandler(db, cfg))

			// Alerts
			protected.GET("/alerts", ListAlertsHandler(db))
			protected.POST("/alerts/:id/ack", AckAlertHandler(db))

			// KEV
			protected.GET("/kev/status", KEVStatusHandler(kevCatalog))

			// Safelists (admin only)
			protected.GET("/safelists", ListSafelistHandler(db))
			protected.POST("/safelists", auth.AdminOnly(), CreateSafelistHandler(db))
			protected.DELETE("/safelists/:id", auth.AdminOnly(), DeleteSafelistHandler(db))

			// Scan Profiles
			protected.GET("/scan-profiles", ListScanProfilesHandler(db))

			// Scan Scopes (admin only)
			protected.GET("/scan-scopes", ListScanScopesHandler(db))
			protected.POST("/scan-scopes", auth.AdminOnly(), CreateScanScopeHandler(db))
			protected.DELETE("/scan-scopes/:id", auth.AdminOnly(), DeleteScanScopeHandler(db))

			// Webhooks (admin only)
			protected.GET("/webhooks", auth.AdminOnly(), ListWebhooksHandler(db))
			protected.POST("/webhooks", auth.AdminOnly(), CreateWebhookHandler(db))
			protected.DELETE("/webhooks/:id", auth.AdminOnly(), DeleteWebhookHandler(db))
			protected.POST("/webhooks/:id/test", auth.AdminOnly(), TestWebhookHandler(db))

			// Users (admin only)
			protected.GET("/users", auth.AdminOnly(), auth.ListUsersHandler(db))
			protected.POST("/users", auth.AdminOnly(), auth.RegisterHandler(db))
		}
	}

	return r
}

// nullableString returns a pointer to a string, or nil if empty.
func nullableString(s string) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return &s
}
