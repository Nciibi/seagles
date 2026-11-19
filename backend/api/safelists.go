package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Nciibi/seagles/alerts"
	"github.com/Nciibi/seagles/auth"
	"github.com/Nciibi/seagles/scanner"
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
		qdb := tenantDB(c, db)
		rows, err := qdb.Query(`SELECT id, entry_type, value, reason, created_by, created_at, is_active
			FROM safelists ORDER BY created_at DESC`)
		if err != nil {
			failInternal(c, 500, "Failed to query safelists: ", err)
			return
		}
		defer rows.Close()

		var entries []SafelistEntry
		for rows.Next() {
			var e SafelistEntry
			var reason, createdBy sql.NullString
			if err := rows.Scan(&e.ID, &e.EntryType, &e.Value, &reason, &createdBy, &e.CreatedAt, &e.IsActive); err != nil {
				failInternal(c, 500, "Failed to read safelist row", err)
				return
			}
			if reason.Valid {
				e.Reason = &reason.String
			}
			if createdBy.Valid {
				e.CreatedBy = &createdBy.String
			}
			entries = append(entries, e)
		}
		if err := rows.Err(); err != nil {
			failInternal(c, 500, "Failed to iterate safelists: ", err)
			return
		}
		if entries == nil {
			entries = []SafelistEntry{}
		}
		success(c, entries)
	}
}

func CreateSafelistHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		qdb := tenantDB(c, db)
		var req CreateSafelistRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			failInternal(c, 400, "Invalid request body", err)
			return
		}

		userID, _ := c.Get("user_id")

		var id string
		err := qdb.QueryRow(`INSERT INTO safelists (tenant_id, entry_type, value, reason, created_by)
			VALUES ($1, $2, $3, $4, $5) RETURNING id`,
			auth.TenantFromContext(c), req.EntryType, req.Value, nullableString(req.Reason), userID).Scan(&id)
		if err != nil {
			failInternal(c, 500, "Failed to create safelist entry: ", err)
			return
		}

		success(c, gin.H{"id": id, "message": "Safelist entry created"})
	}
}

func DeleteSafelistHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		qdb := tenantDB(c, db)
		id, ok := uuidParam(c, "id")
		if !ok {
			return
		}
		result, err := qdb.Exec(`UPDATE safelists SET is_active = FALSE WHERE id = $1`, id)
		if err != nil {
			failInternal(c, 500, "Failed to delete safelist entry: ", err)
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

func IsSafelisted(db DBTX, ip, tenantID string) bool {
	var count int
	db.QueryRow(`SELECT COUNT(*) FROM safelists
		WHERE tenant_id = $2 AND is_active = TRUE AND (
			(entry_type = 'ip' AND value = $1) OR
			(entry_type = 'cidr' AND $1::inet <<= value::cidr)
		)`, ip, tenantID).Scan(&count)
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
		qdb := tenantDB(c, db)
		rows, err := qdb.Query(`SELECT id, name, description, skip_credential_test, skip_protocol_probe,
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
				failInternal(c, 500, "Failed to read scan profile row", err)
				return
			}
			if desc.Valid {
				p.Description = desc.String
			}
			profiles = append(profiles, p)
		}
		if err := rows.Err(); err != nil {
			fail(c, 500, "Failed to iterate scan profiles")
			return
		}
		if profiles == nil {
			profiles = []ScanProfile{}
		}
		success(c, profiles)
	}
}

type ScanProfileRequest struct {
	Name               string `json:"name" binding:"required,min=1,max=100"`
	Description        string `json:"description" binding:"max=500"`
	SkipCredentialTest bool   `json:"skip_credential_test"`
	SkipProtocolProbe  bool   `json:"skip_protocol_probe"`
	MaxPortCount       int    `json:"max_port_count" binding:"omitempty,min=1,max=100"`
	TimeoutSeconds     int    `json:"timeout_seconds" binding:"omitempty,min=1,max=3600"`
}

func CreateScanProfileHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req ScanProfileRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			failInternal(c, 400, "Invalid request body", err)
			return
		}
		if req.MaxPortCount == 0 {
			req.MaxPortCount = len(scanner.DefaultScanPorts)
		}
		if req.TimeoutSeconds == 0 {
			req.TimeoutSeconds = 90
		}

		var id string
		err := tenantDB(c, db).QueryRow(`INSERT INTO scan_profiles
			(tenant_id, name, description, skip_credential_test, skip_protocol_probe, max_port_count, timeout_seconds)
			VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
			auth.TenantFromContext(c), req.Name, nullableString(req.Description),
			req.SkipCredentialTest, req.SkipProtocolProbe, req.MaxPortCount, req.TimeoutSeconds,
		).Scan(&id)
		if err != nil {
			if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
				fail(c, 409, "A scan profile with that name already exists")
				return
			}
			failInternal(c, 500, "Failed to create scan profile", err)
			return
		}
		success(c, gin.H{"id": id, "message": "Scan profile created"})
	}
}

func UpdateScanProfileHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, ok := uuidParam(c, "id")
		if !ok {
			return
		}
		var req ScanProfileRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			failInternal(c, 400, "Invalid request body", err)
			return
		}
		if req.MaxPortCount == 0 {
			req.MaxPortCount = len(scanner.DefaultScanPorts)
		}
		if req.TimeoutSeconds == 0 {
			req.TimeoutSeconds = 90
		}

		result, err := tenantDB(c, db).Exec(`UPDATE scan_profiles SET
			name=$1, description=$2, skip_credential_test=$3, skip_protocol_probe=$4,
			max_port_count=$5, timeout_seconds=$6
			WHERE id=$7 AND tenant_id=$8`,
			req.Name, nullableString(req.Description), req.SkipCredentialTest,
			req.SkipProtocolProbe, req.MaxPortCount, req.TimeoutSeconds, id, auth.TenantFromContext(c))
		if err != nil {
			failInternal(c, 500, "Failed to update scan profile", err)
			return
		}
		n, _ := result.RowsAffected()
		if n == 0 {
			fail(c, 404, "Scan profile not found")
			return
		}
		success(c, gin.H{"message": "Scan profile updated"})
	}
}

func DeleteScanProfileHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, ok := uuidParam(c, "id")
		if !ok {
			return
		}
		result, err := tenantDB(c, db).Exec(`DELETE FROM scan_profiles WHERE id=$1 AND tenant_id=$2 AND is_default=FALSE`,
			id, auth.TenantFromContext(c))
		if err != nil {
			if strings.Contains(err.Error(), "foreign key") || strings.Contains(err.Error(), "violates") {
				fail(c, 409, "Scan profile is referenced by existing scans")
				return
			}
			failInternal(c, 500, "Failed to delete scan profile", err)
			return
		}
		n, _ := result.RowsAffected()
		if n == 0 {
			fail(c, 404, "Scan profile not found (default profiles cannot be deleted)")
			return
		}
		success(c, gin.H{"message": "Scan profile deleted"})
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
		qdb := tenantDB(c, db)
		rows, err := qdb.Query(`SELECT id, cidr, label, is_active FROM scan_scopes ORDER BY created_at DESC`)
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
				failInternal(c, 500, "Failed to read scan scope row", err)
				return
			}
			if label.Valid {
				s.Label = label.String
			}
			scopes = append(scopes, s)
		}
		if err := rows.Err(); err != nil {
			fail(c, 500, "Failed to iterate scan scopes")
			return
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
		qdb := tenantDB(c, db)
		var req CreateScanScopeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			failInternal(c, 400, "Invalid request body", err)
			return
		}

		var id string
		err := qdb.QueryRow(`INSERT INTO scan_scopes (tenant_id, cidr, label) VALUES ($1, $2, $3) RETURNING id`,
			auth.TenantFromContext(c), req.CIDR, nullableString(req.Label)).Scan(&id)
		if err != nil {
			failInternal(c, 500, "Failed to create scan scope: ", err)
			return
		}

		success(c, gin.H{"id": id, "message": "Scan scope created"})
	}
}

func DeleteScanScopeHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		qdb := tenantDB(c, db)
		id, ok := uuidParam(c, "id")
		if !ok {
			return
		}
		result, err := qdb.Exec(`UPDATE scan_scopes SET is_active = FALSE WHERE id = $1`, id)
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
		qdb := tenantDB(c, db)
		rows, err := qdb.Query(`SELECT id, name, url, webhook_type, min_severity, is_active, last_triggered
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
				failInternal(c, 500, "Failed to read webhook row", err)
				return
			}
			if lastTriggered.Valid {
				w.LastTriggered = &lastTriggered.String
			}
			webhooks = append(webhooks, w)
		}
		if err := rows.Err(); err != nil {
			fail(c, 500, "Failed to iterate webhooks")
			return
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
	WebhookType string `json:"webhook_type" binding:"required,oneof=slack teams generic syslog"`
	MinSeverity string `json:"min_severity" binding:"omitempty,oneof=critical high medium low"`
}

func CreateWebhookHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		qdb := tenantDB(c, db)
		var req CreateWebhookRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			failInternal(c, 400, "Invalid request body", err)
			return
		}

		if req.MinSeverity == "" {
			req.MinSeverity = "high"
		}

		if err := alerts.ValidateWebhookTarget(req.URL, req.WebhookType); err != nil {
			failInternal(c, 400, "Invalid webhook target", err)
			return
		}

		var id string
		err := qdb.QueryRow(`INSERT INTO webhooks (tenant_id, name, url, webhook_type, min_severity)
			VALUES ($1, $2, $3, $4, $5) RETURNING id`,
			auth.TenantFromContext(c), req.Name, req.URL, req.WebhookType, req.MinSeverity).Scan(&id)
		if err != nil {
			failInternal(c, 500, "Failed to create webhook: ", err)
			return
		}

		success(c, gin.H{"id": id, "message": fmt.Sprintf("Webhook '%s' created", req.Name)})
	}
}

func DeleteWebhookHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		qdb := tenantDB(c, db)
		id, ok := uuidParam(c, "id")
		if !ok {
			return
		}
		result, err := qdb.Exec(`DELETE FROM webhooks WHERE id = $1`, id)
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
		qdb := tenantDB(c, db)
		id, ok := uuidParam(c, "id")
		if !ok {
			return
		}
		var webhookURL, webhookType string
		err := qdb.QueryRow(`SELECT url, webhook_type FROM webhooks WHERE id=$1`, id).Scan(&webhookURL, &webhookType)
		if err != nil {
			fail(c, 404, "Webhook not found")
			return
		}
		if err := alerts.ValidateWebhookTarget(webhookURL, webhookType); err != nil {
			failInternal(c, 400, "Invalid webhook target", err)
			return
		}
		testPayload := map[string]interface{}{
			"event":     "test",
			"message":   "This is a test webhook from Seagles",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}
		body, _ := json.Marshal(testPayload)
		req, err := http.NewRequest("POST", webhookURL, bytes.NewReader(body))
		if err != nil {
			failInternal(c, 400, "Invalid webhook target", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			failInternal(c, 502, "Failed to send test webhook", err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			fail(c, 502, fmt.Sprintf("Webhook responded with HTTP %d", resp.StatusCode))
			return
		}
		success(c, gin.H{"status": "test_webhook_sent"})
	}
}
