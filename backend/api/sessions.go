package api

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/Nciibi/seagles/slog"
)

type SessionInfo struct {
	ID           string  `json:"id"`
	UserID       string  `json:"user_id"`
	Username     string  `json:"username"`
	IPAddress    string  `json:"ip_address"`
	UserAgent    string  `json:"user_agent"`
	CreatedAt    string  `json:"created_at"`
	ExpiresAt    string  `json:"expires_at"`
	IsRevoked    bool    `json:"is_revoked"`
	IsCurrent    bool    `json:"is_current"`
}

func ListSessionsHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			fail(c, http.StatusUnauthorized, "User not authenticated")
			return
		}

		isAdmin, _ := c.Get("role")
		adminMode := isAdmin == "admin" && c.Query("user_id") != ""

		var queryUserID string
		if adminMode {
			queryUserID = c.Query("user_id")
		} else {
			queryUserID = userID.(string)
		}

		rows, err := db.Query(`
			SELECT id, user_id, username, ip_address, user_agent, created_at, expires_at, revoked
			FROM refresh_tokens
			WHERE user_id = $1
			ORDER BY created_at DESC
			LIMIT 100`, queryUserID)
		if err != nil {
			slog.Error("failed to list sessions", "error", err.Error())
			fail(c, http.StatusInternalServerError, "Failed to list sessions")
			return
		}
		defer rows.Close()

		sessions := make([]SessionInfo, 0)
		for rows.Next() {
			var s SessionInfo
			if err := rows.Scan(&s.ID, &s.UserID, &s.Username, &s.IPAddress, &s.UserAgent, &s.CreatedAt, &s.ExpiresAt, &s.IsRevoked); err != nil {
				continue
			}
			s.IsCurrent = s.ID == c.GetString("token_id")
			sessions = append(sessions, s)
		}

		success(c, sessions)
	}
}

func RevokeSessionHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID := c.Param("id")

		result, err := db.Exec(`UPDATE refresh_tokens SET revoked = TRUE WHERE id = $1`, sessionID)
		if err != nil {
			slog.Error("failed to revoke session", "id", sessionID, "error", err.Error())
			fail(c, http.StatusInternalServerError, "Failed to revoke session")
			return
		}

		rows, _ := result.RowsAffected()
		if rows == 0 {
			fail(c, http.StatusNotFound, "Session not found")
			return
		}

		success(c, gin.H{"message": "Session revoked successfully"})
	}
}
