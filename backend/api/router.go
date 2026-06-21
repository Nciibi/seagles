package api

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
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

	v1 := r.Group("/api/v1")
	{
		// Stats
		v1.GET("/stats", StatsHandler(db))

		// Devices
		v1.GET("/devices", ListDevicesHandler(db))
		v1.GET("/devices/:id", GetDeviceHandler(db))
		v1.DELETE("/devices/:id", DeleteDeviceHandler(db))
		v1.POST("/devices/:id/scan", TriggerDeviceScanHandler(db, cfg, kevCatalog))
		v1.GET("/devices/:id/risk-breakdown", RiskBreakdownHandler(db))

		// Scans
		v1.GET("/scans", ListScansHandler(db))
		v1.GET("/scans/:id", GetScanHandler(db))
		v1.POST("/scan/network", NetworkScanHandler(db, cfg))

		// Vulnerabilities
		v1.GET("/vulnerabilities", ListVulnerabilitiesHandler(db))
		v1.PATCH("/vulnerabilities/:id/resolve", ResolveVulnerabilityHandler(db))

		// Firmware
		v1.GET("/firmware", ListFirmwareHandler(db))
		v1.POST("/firmware/:id/analyze", AnalyzeFirmwareHandler(db, cfg))

		// Alerts
		v1.GET("/alerts", ListAlertsHandler(db))
		v1.POST("/alerts/:id/ack", AckAlertHandler(db))

		// KEV
		v1.GET("/kev/status", KEVStatusHandler(kevCatalog))
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
