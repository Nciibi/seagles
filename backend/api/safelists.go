package api

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Safelist entry types
const (
	SafelistTypeIP   = "ip"
	SafelistTypeCIDR = "cidr"
	SafelistTypeMAC  = "mac"
)

// SafelistEntry represents a safelist entry.
type SafelistEntry struct {
	ID        string  `json:"id"`
	EntryType string  `json:"entry_type"`
	Value     string  `json:"value"`
	Reason    *string `json:"reason"`
	CreatedBy *string `json:"created_by"`
	CreatedAt string  `json:"created_at"`
	IsActive  bool    `json:"is_active"`
}

// CreateSafelistRequest is the request body for creating a safelist entry.
type CreateSafelistRequest struct {
	EntryType string `json:"entry_type" binding:"required"`
	Value     string `json:"value" binding:"required"`
	Reason    string `json:"reason"`
}

// ListSafelistHandler returns all active safelist entries.
func ListSafelistHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		rows, err := db.Query(`SELECT id, entry_type, value, reason, created_by, created_at, is_active
			FROM safelists ORDER BY created_at DESC`)
		if err != nil {
			fail(c, 500, "Failed to query safelists: "+err.Error())
			return
		}
		defer rows.Close()

		var entries []SafelistEntry
		for rows.Next() {
			var e SafelistEntry
			var reason, createdBy sql.NullString
			if err := rows.Scan(&e.ID, &e.EntryType, &e.Value, &reason, &createdBy, &e.CreatedAt, &e.IsActive); err != nil {
				continue
			}
			if reason.Valid {
				e.Reason = &reason.String
			}
			if createdBy.Valid {
				e.CreatedBy = &createdBy.String
			}
			entries = append(entries, e)
		}
		if entries == nil {
			entries = []SafelistEntry{}
		}
		success(c, entries)
	}
}

// CreateSafelistHandler adds a new safelist entry.
func CreateSafelistHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req CreateSafelistRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			fail(c, 400, "Invalid request: "+err.Error())
			return
		}

		if req.EntryType != SafelistTypeIP && req.EntryType != SafelistTypeCIDR && req.EntryType != SafelistTypeMAC {
			fail(c, 400, "entry_type must be 'ip', 'cidr', or 'mac'")
			return
		}

		userID, _ := c.Get("user_id")

		var id string
		err := db.QueryRow(`INSERT INTO safelists (entry_type, value, reason, created_by)
			VALUES ($1, $2, $3, $4) RETURNING id`,
			req.EntryType, req.Value, nullableString(req.Reason), userID).Scan(&id)
		if err != nil {
			fail(c, 500, "Failed to create safelist entry: "+err.Error())
			return
		}

		success(c, gin.H{"id": id, "message": "Safelist entry created"})
	}
}

// DeleteSafelistHandler deactivates a safelist entry.
func DeleteSafelistHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		result, err := db.Exec(`UPDATE safelists SET is_active = FALSE WHERE id = $1`, id)
		if err != nil {
			fail(c, 500, "Failed to delete safelist entry: "+err.Error())
			return
		}
		n, _ := result.RowsAffected()
		if n == 0 {
			fail(c, 404, "Safelist entry not found")
			return
		}
		success(c, gin.H{"message": "Safelist entry deactivated"})
	}
}

// IsSafelisted checks if an IP address is in the safelist.
func IsSafelisted(db *sql.DB, ip string) bool {
	var count int
	db.QueryRow(`SELECT COUNT(*) FROM safelists
		WHERE is_active = TRUE AND (
			(entry_type = 'ip' AND value = $1) OR
			(entry_type = 'cidr' AND $1::inet <<= value::cidr)
		)`, ip).Scan(&count)
	return count > 0
}

// --- Scan Profiles ---

// ScanProfile represents a scan configuration profile.
type ScanProfile struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Description        string `json:"description"`
	SkipCredentialTest bool   `json:"skip_credential_test"`
	SkipProtocolProbe  bool   `json:"skip_protocol_probe"`
	MaxPortCount       int    `json:"max_port_count"`
	TimeoutSeconds     int    `json:"timeout_seconds"`
	IsDefault          bool   `json:"is_default"`
}

// ListScanProfilesHandler returns all scan profiles.
func ListScanProfilesHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		rows, err := db.Query(`SELECT id, name, description, skip_credential_test, skip_protocol_probe,
			max_port_count, timeout_seconds, is_default FROM scan_profiles ORDER BY name`)
		if err != nil {
			fail(c, 500, "Failed to query scan profiles")
			return
		}
		defer rows.Close()

		var profiles []ScanProfile
		for rows.Next() {
			var p ScanProfile
			var desc sql.NullString
			if err := rows.Scan(&p.ID, &p.Name, &desc, &p.SkipCredentialTest, &p.SkipProtocolProbe,
				&p.MaxPortCount, &p.TimeoutSeconds, &p.IsDefault); err != nil {
				continue
			}
			if desc.Valid {
				p.Description = desc.String
			}
			profiles = append(profiles, p)
		}
		if profiles == nil {
			profiles = []ScanProfile{}
		}
		success(c, profiles)
	}
}

// --- Scan Scopes ---

// ScanScope represents a network CIDR scope.
type ScanScope struct {
	ID       string `json:"id"`
	CIDR     string `json:"cidr"`
	Label    string `json:"label"`
	IsActive bool   `json:"is_active"`
}

// ListScanScopesHandler returns all scan scopes.
func ListScanScopesHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		rows, err := db.Query(`SELECT id, cidr, label, is_active FROM scan_scopes ORDER BY created_at DESC`)
		if err != nil {
			fail(c, 500, "Failed to query scan scopes")
			return
		}
		defer rows.Close()

		var scopes []ScanScope
		for rows.Next() {
			var s ScanScope
			var label sql.NullString
			if err := rows.Scan(&s.ID, &s.CIDR, &label, &s.IsActive); err != nil {
				continue
			}
			if label.Valid {
				s.Label = label.String
			}
			scopes = append(scopes, s)
		}
		if scopes == nil {
			scopes = []ScanScope{}
		}
		success(c, scopes)
	}
}

// CreateScanScopeHandler adds a new scan scope.
func CreateScanScopeHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			CIDR  string `json:"cidr" binding:"required"`
			Label string `json:"label"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			fail(c, 400, "CIDR is required")
			return
		}

		var id string
		err := db.QueryRow(`INSERT INTO scan_scopes (cidr, label) VALUES ($1, $2) RETURNING id`,
			req.CIDR, nullableString(req.Label)).Scan(&id)
		if err != nil {
			fail(c, 500, "Failed to create scan scope: "+err.Error())
			return
		}

		success(c, gin.H{"id": id, "message": "Scan scope created"})
	}
}

// DeleteScanScopeHandler deactivates a scan scope.
func DeleteScanScopeHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		result, err := db.Exec(`UPDATE scan_scopes SET is_active = FALSE WHERE id = $1`, id)
		if err != nil {
			fail(c, 500, "Failed to delete scan scope")
			return
		}
		n, _ := result.RowsAffected()
		if n == 0 {
			fail(c, 404, "Scan scope not found")
			return
		}
		success(c, gin.H{"message": "Scan scope deactivated"})
	}
}

// --- Webhooks ---

// WebhookInfo represents a webhook for API responses.
type WebhookInfo struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	URL           string  `json:"url"`
	WebhookType   string  `json:"webhook_type"`
	MinSeverity   string  `json:"min_severity"`
	IsActive      bool    `json:"is_active"`
	LastTriggered *string `json:"last_triggered"`
}

// ListWebhooksHandler returns all configured webhooks.
func ListWebhooksHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		rows, err := db.Query(`SELECT id, name, url, webhook_type, min_severity, is_active, last_triggered
			FROM webhooks ORDER BY created_at DESC`)
		if err != nil {
			fail(c, 500, "Failed to query webhooks")
			return
		}
		defer rows.Close()

		var webhooks []WebhookInfo
		for rows.Next() {
			var w WebhookInfo
			var lastTriggered sql.NullString
			if err := rows.Scan(&w.ID, &w.Name, &w.URL, &w.WebhookType, &w.MinSeverity, &w.IsActive, &lastTriggered); err != nil {
				continue
			}
			if lastTriggered.Valid {
				w.LastTriggered = &lastTriggered.String
			}
			webhooks = append(webhooks, w)
		}
		if webhooks == nil {
			webhooks = []WebhookInfo{}
		}
		success(c, webhooks)
	}
}

// CreateWebhookHandler adds a new webhook.
func CreateWebhookHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Name        string `json:"name" binding:"required"`
			URL         string `json:"url" binding:"required"`
			WebhookType string `json:"webhook_type" binding:"required"`
			MinSeverity string `json:"min_severity"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			fail(c, 400, "Invalid request: "+err.Error())
			return
		}

		if req.MinSeverity == "" {
			req.MinSeverity = "high"
		}

		var id string
		err := db.QueryRow(`INSERT INTO webhooks (name, url, webhook_type, min_severity)
			VALUES ($1, $2, $3, $4) RETURNING id`,
			req.Name, req.URL, req.WebhookType, req.MinSeverity).Scan(&id)
		if err != nil {
			fail(c, 500, "Failed to create webhook: "+err.Error())
			return
		}

		success(c, gin.H{"id": id, "message": fmt.Sprintf("Webhook '%s' created", req.Name)})
	}
}

// DeleteWebhookHandler removes a webhook.
func DeleteWebhookHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		result, err := db.Exec(`DELETE FROM webhooks WHERE id = $1`, id)
		if err != nil {
			fail(c, 500, "Failed to delete webhook")
			return
		}
		n, _ := result.RowsAffected()
		if n == 0 {
			fail(c, 404, "Webhook not found")
			return
		}
		success(c, gin.H{"message": "Webhook deleted"})
	}
}

// TestWebhookHandler sends a test alert to a webhook.
func TestWebhookHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		var url, webhookType string
		err := db.QueryRow(`SELECT url, webhook_type FROM webhooks WHERE id = $1`, id).Scan(&url, &webhookType)
		if err != nil {
			fail(c, http.StatusNotFound, "Webhook not found")
			return
		}

		success(c, gin.H{"message": "Test webhook sent", "webhook_id": id})
	}
}
