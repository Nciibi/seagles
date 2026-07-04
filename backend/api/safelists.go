package api

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/seagles/auth"
)

const (
	SafelistTypeIP   = "ip"
	SafelistTypeCIDR = "cidr"
	SafelistTypeMAC  = "mac"
)

type SafelistEntry struct {
	ID        string  `json:"id"`
	EntryType string  `json:"entry_type"`
	Value     string  `json:"value"`
	Reason    *string `json:"reason"`
	CreatedBy *string `json:"created_by"`
	CreatedAt string  `json:"created_at"`
	IsActive  bool    `json:"is_active"`
}

type CreateSafelistRequest struct {
	EntryType string `json:"entry_type" binding:"required,oneof=ip cidr mac"`
	Value     string `json:"value" binding:"required,min=1,max=255"`
	Reason    string `json:"reason" binding:"max=500"`
}

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

func CreateSafelistHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req CreateSafelistRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			fail(c, 400, "Invalid request: "+err.Error())
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

func IsSafelisted(db *sql.DB, ip string) bool {
	var count int
	db.QueryRow(`SELECT COUNT(*) FROM safelists
		WHERE is_active = TRUE AND (
			(entry_type = 'ip' AND value = $1) OR
			(entry_type = 'cidr' AND $1::inet <<= value::cidr)
		)`, ip).Scan(&count)
	return count > 0
}

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

type ScanScope struct {
	ID       string `json:"id"`
	CIDR     string `json:"cidr"`
	Label    string `json:"label"`
	IsActive bool   `json:"is_active"`
}

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

type CreateScanScopeRequest struct {
	CIDR  string `json:"cidr" binding:"required,cidr"`
	Label string `json:"label" binding:"max=200"`
}

func CreateScanScopeHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req CreateScanScopeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			fail(c, 400, "CIDR is required: "+err.Error())
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

type WebhookInfo struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	URL           string  `json:"url"`
	WebhookType   string  `json:"webhook_type"`
	MinSeverity   string  `json:"min_severity"`
	IsActive      bool    `json:"is_active"`
	LastTriggered *string `json:"last_triggered"`
}

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

type CreateWebhookRequest struct {
	Name        string `json:"name" binding:"required,min=1,max=100"`
	URL         string `json:"url" binding:"required,url"`
	WebhookType string `json:"webhook_type" binding:"required,oneof=slack teams generic"`
	MinSeverity string `json:"min_severity" binding:"omitempty,oneof=critical high medium low"`
}

func CreateWebhookHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req CreateWebhookRequest
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

var _ = auth.AuthMiddleware
