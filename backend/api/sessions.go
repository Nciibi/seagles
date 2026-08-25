package api

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/Nciibi/seagles/slog"
)

type SessionInfo struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IsRevoked bool      `json:"is_revoked"`
	// IsCurrent is always false for now: an access token does not carry the
	// identity of the refresh token (session) it was issued from, so the
	// current session cannot be reliably identified. The field is kept for
	// API compatibility with the frontend.
	IsCurrent bool `json:"is_current"`
}

func ListSessionsHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			fail(c, http.StatusUnauthorized, "User not authenticated")
			return
		}

		roleVal, _ := c.Get("user_role")
		roleStr, _ := roleVal.(string)
		adminMode := roleStr == "admin" && c.Query("user_id") != ""

		var queryUserID string
		if adminMode {
			queryUserID = c.Query("user_id")
		} else if uid, ok := userID.(string); ok {
			queryUserID = uid
		} else {
			fail(c, http.StatusUnauthorized, "User not authenticated")
			return
		}

		rows, err := db.Query(`
			SELECT rt.id, rt.user_id, u.username, rt.created_at, rt.expires_at, rt.revoked
			FROM refresh_tokens rt
			JOIN users u ON u.id = rt.user_id
			WHERE rt.user_id = $1
			ORDER BY rt.created_at DESC
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
			if err := rows.Scan(&s.ID, &s.UserID, &s.Username, &s.CreatedAt, &s.ExpiresAt, &s.IsRevoked); err != nil {
				slog.Warn("failed to scan session row", "error", err.Error())
				continue
			}
			sessions = append(sessions, s)
		}
		if err := rows.Err(); err != nil {
			fail(c, 500, "Failed to iterate sessions: "+err.Error())
			return
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
