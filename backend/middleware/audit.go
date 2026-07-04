package middleware

import (
	"database/sql"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/Nciibi/seagles/slog"
)

type AuditEntry struct {
	UserID    string
	Username  string
	Action    string
	Resource  string
	ResourcID string
	Detail    string
	IPAddress string
	UserAgent string
	Status    int
	LatencyMs int
}

var writeMethods = []string{"POST", "PUT", "PATCH", "DELETE"}

func isWriteMethod(method string) bool {
	for _, m := range writeMethods {
		if method == m {
			return true
		}
	}
	return false
}

func AuditLogger(db *sql.DB, skipPaths ...string) gin.HandlerFunc {
	skipMap := make(map[string]bool, len(skipPaths))
	for _, p := range skipPaths {
		skipMap[p] = true
	}

	return func(c *gin.Context) {
		if skipMap[c.Request.URL.Path] {
			c.Next()
			return
		}

		start := time.Now()

		c.Next()

		if !isWriteMethod(c.Request.Method) {
			return
		}

		latencyMs := int(time.Since(start).Microseconds() / 1000)

		userID, _ := c.Get("user_id")
		username, _ := c.Get("username")

		userIDStr, _ := userID.(string)
		usernameStr, _ := username.(string)

		entry := AuditEntry{
			UserID:    userIDStr,
			Username:  usernameStr,
			Action:    c.Request.Method,
			Resource:  c.Request.URL.Path,
			ResourcID: c.Param("id"),
			IPAddress: c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Status:    c.Writer.Status(),
			LatencyMs: latencyMs,
		}

		_, err := db.Exec(
			`INSERT INTO audit_log (user_id, username, action, resource, resource_id, ip_address, user_agent, status_code, latency_ms)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			entry.UserID, entry.Username, entry.Action, entry.Resource,
			entry.ResourcID, entry.IPAddress, entry.UserAgent,
			entry.Status, entry.LatencyMs,
		)
		if err != nil {
			slog.Debug("audit_log_failed", "error", err.Error())
		}
	}
}

func ListAuditLogsHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		limit := 100
		offset := 0

		rows, err := db.Query(
			`SELECT id, user_id, username, action, resource, resource_id, detail,
			        ip_address, user_agent, status_code, latency_ms, created_at
			 FROM audit_log ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
			limit, offset,
		)
		if err != nil {
			c.JSON(500, gin.H{"data": nil, "error": "Failed to query audit log"})
			return
		}
		defer rows.Close()

		type AuditLogEntry struct {
			ID         string     `json:"id"`
			UserID     *string    `json:"user_id"`
			Username   string     `json:"username"`
			Action     string     `json:"action"`
			Resource   string     `json:"resource"`
			ResourceID *string    `json:"resource_id"`
			Detail     *string    `json:"detail"`
			IPAddress  string     `json:"ip_address"`
			UserAgent  string     `json:"user_agent"`
			StatusCode int        `json:"status_code"`
			LatencyMs  int        `json:"latency_ms"`
			CreatedAt  time.Time  `json:"created_at"`
		}

		var entries []AuditLogEntry
		for rows.Next() {
			var e AuditLogEntry
			var uid, rid, detail sql.NullString
			if err := rows.Scan(&e.ID, &uid, &e.Username, &e.Action, &e.Resource, &rid, &detail,
				&e.IPAddress, &e.UserAgent, &e.StatusCode, &e.LatencyMs, &e.CreatedAt); err != nil {
				continue
			}
			if uid.Valid {
				e.UserID = &uid.String
			}
			if rid.Valid {
				e.ResourceID = &rid.String
			}
			if detail.Valid {
				e.Detail = &detail.String
			}
			entries = append(entries, e)
		}
		if err := rows.Err(); err != nil {
			log.Printf("Error iterating audit logs: %v", err)
			return
		}
		if entries == nil {
			entries = []AuditLogEntry{}
		}

		c.JSON(200, gin.H{"data": entries, "error": nil})
	}
}
