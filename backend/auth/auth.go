package auth

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/Nciibi/seagles/cache"
	"github.com/Nciibi/seagles/slog"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required,min=1,max=100"`
	Password string `json:"password" binding:"required,min=8,max=128"`
}

type LoginResponse struct {
	Token        string `json:"token"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	User         User   `json:"user"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50,alphanum"`
	Email    string `json:"email" binding:"required,email,max=255"`
	Password string `json:"password" binding:"required,min=8,max=128"`
	Role     string `json:"role" binding:"omitempty,oneof=admin viewer operator auditor"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required,min=8,max=128"`
	NewPassword     string `json:"new_password" binding:"required,min=8,max=128"`
}

func SetJWTSecret(secret string) {
	if err := LoadOrGenerateKeys(secret); err != nil {
		slog.Fatal("Failed to initialize RSA key pair", "error", err.Error())
	}
}

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

func CheckPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func storeRefreshToken(db *sql.DB, userID, tokenID string, expiresAt time.Time) error {
	tokenHash := sha256.Sum256([]byte(tokenID))
	_, err := db.Exec(
		`INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
		userID, hex.EncodeToString(tokenHash[:]), expiresAt,
	)
	return err
}

func validateRefreshToken(db *sql.DB, refreshToken string) (*User, error) {
	parts := strings.SplitN(refreshToken, ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("invalid refresh token format")
	}

	tokenID := parts[0]
	tokenHash := sha256.Sum256([]byte(tokenID))
	tokenHashHex := hex.EncodeToString(tokenHash[:])

	var user User
	var expiresAt time.Time
	var revoked bool
	err := db.QueryRow(
		`SELECT u.id, u.username, u.email, u.role, rt.expires_at, rt.revoked
		 FROM refresh_tokens rt JOIN users u ON u.id = rt.user_id
		 WHERE rt.token_hash = $1 AND rt.revoked = FALSE AND rt.expires_at > NOW()`,
		tokenHashHex,
	).Scan(&user.ID, &user.Username, &user.Email, &user.Role, &expiresAt, &revoked)
	if err == sql.ErrNoRows {
		return nil, errors.New("invalid or expired refresh token")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query refresh token: %w", err)
	}

	return &user, nil
}

func revokeAllRefreshTokens(db *sql.DB, userID string) error {
	_, err := db.Exec(`UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1 AND revoked = FALSE`, userID)
	return err
}

func revokeRefreshTokenByID(db *sql.DB, tokenID string) error {
	tokenHash := sha256.Sum256([]byte(tokenID))
	_, err := db.Exec(
		`UPDATE refresh_tokens SET revoked = TRUE WHERE token_hash = $1`,
		hex.EncodeToString(tokenHash[:]),
	)
	return err
}

func LoginHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"data": nil, "error": "Invalid credentials format: " + err.Error()})
			return
		}

		var user User
		var passwordHash string
		err := db.QueryRow(
			`SELECT id, username, email, role, password_hash FROM users WHERE username = $1 AND is_active = TRUE`,
			req.Username,
		).Scan(&user.ID, &user.Username, &user.Email, &user.Role, &passwordHash)

		if err == sql.ErrNoRows {
			slog.Warn("login_failed", "username", req.Username, "reason", "invalid_credentials")
			c.JSON(http.StatusUnauthorized, gin.H{"data": nil, "error": "Invalid credentials"})
			return
		}
		if err != nil {
			slog.Error("login_error", "username", req.Username, "error", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"data": nil, "error": "Authentication failed"})
			return
		}

		if !CheckPassword(req.Password, passwordHash) {
			slog.Warn("login_failed", "username", req.Username, "reason", "wrong_password")
			c.JSON(http.StatusUnauthorized, gin.H{"data": nil, "error": "Invalid credentials"})
			return
		}

		db.Exec(`UPDATE users SET last_login = NOW() WHERE id = $1`, user.ID)

		accessToken, err := GenerateAccessToken(user)
		if err != nil {
			slog.Error("token_generation_failed", "error", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"data": nil, "error": "Failed to generate token"})
			return
		}

		refreshTokenID := generateTokenID()
		refreshExpiry := time.Now().Add(RefreshTokenTTL)
		if err := storeRefreshToken(db, user.ID, refreshTokenID, refreshExpiry); err != nil {
			slog.Error("refresh_token_store_failed", "error", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"data": nil, "error": "Failed to generate refresh token"})
			return
		}

		refreshToken := refreshTokenID + "." + user.ID

		slog.Info("login_success", "username", user.Username, "role", user.Role)

		c.JSON(http.StatusOK, gin.H{
			"data": LoginResponse{
				Token:        accessToken.Token,
				ExpiresIn:    int64(time.Until(time.Unix(accessToken.Claims.Exp, 0)).Seconds()),
				RefreshToken: refreshToken,
				User:         user,
			},
			"error": nil,
		})
	}
}

func RegisterHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req RegisterRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"data": nil, "error": "Invalid request: " + err.Error()})
			return
		}

		role := "viewer"
		switch req.Role {
		case "admin", "operator", "auditor":
			role = req.Role
		}

		hash, err := HashPassword(req.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"data": nil, "error": "Failed to hash password"})
			return
		}

		var userID string
		err = db.QueryRow(
			`INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id`,
			req.Username, req.Email, hash, role,
		).Scan(&userID)

		if err != nil {
			if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
				c.JSON(http.StatusConflict, gin.H{"data": nil, "error": "Username or email already exists"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"data": nil, "error": "Failed to create user"})
			return
		}

		slog.Info("user_registered", "username", req.Username, "role", role)

		c.JSON(http.StatusCreated, gin.H{
			"data":  gin.H{"id": userID, "username": req.Username, "role": role},
			"error": nil,
		})
	}
}

func RefreshTokenHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req RefreshRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"data": nil, "error": "Invalid request: " + err.Error()})
			return
		}

		user, err := validateRefreshToken(db, req.RefreshToken)
		if err != nil {
			slog.Warn("refresh_failed", "error", err.Error())
			c.JSON(http.StatusUnauthorized, gin.H{"data": nil, "error": "Invalid or expired refresh token"})
			return
		}

		accessToken, err := GenerateAccessToken(*user)
		if err != nil {
			slog.Error("token_generation_failed", "error", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"data": nil, "error": "Failed to generate token"})
			return
		}

		refreshTokenID := generateTokenID()
		refreshExpiry := time.Now().Add(RefreshTokenTTL)
		if err := storeRefreshToken(db, user.ID, refreshTokenID, refreshExpiry); err != nil {
			slog.Error("refresh_token_store_failed", "error", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"data": nil, "error": "Failed to generate refresh token"})
			return
		}

		newRefreshToken := refreshTokenID + "." + user.ID

		slog.Info("token_refreshed", "username", user.Username)

		c.JSON(http.StatusOK, gin.H{
			"data": gin.H{
				"token":         accessToken.Token,
				"expires_in":    int64(time.Until(time.Unix(accessToken.Claims.Exp, 0)).Seconds()),
				"refresh_token": newRefreshToken,
			},
			"error": nil,
		})
	}
}

func LogoutHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"data": nil, "error": "Authorization header required"})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"data": nil, "error": "Invalid authorization format"})
			return
		}

		claims, err := verifyRS256(parts[1])
		if err == nil && claims != nil {
			cache.BlacklistToken(claims.JTI)
		}

		userID, _ := c.Get("user_id")
		slog.Info("user_logout", "user_id", userID)
		c.JSON(http.StatusOK, gin.H{"data": "Logged out successfully", "error": nil})
	}
}

func ChangePasswordHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDVal, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"data": nil, "error": "Not authenticated"})
			return
		}
		userID, ok := userIDVal.(string)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"data": nil, "error": "Invalid user identity"})
			return
		}

		usernameVal, _ := c.Get("username")
		username := ""
		if usernameVal != nil {
			username, _ = usernameVal.(string)
		}

		var req ChangePasswordRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"data": nil, "error": "Invalid request: " + err.Error()})
			return
		}

		var passwordHash string
		err := db.QueryRow(`SELECT password_hash FROM users WHERE id = $1`, userID).Scan(&passwordHash)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"data": nil, "error": "Failed to verify current password"})
			return
		}

		if !CheckPassword(req.CurrentPassword, passwordHash) {
			slog.Warn("password_change_failed", "username", username, "reason", "wrong_current_password")
			c.JSON(http.StatusForbidden, gin.H{"data": nil, "error": "Current password is incorrect"})
			return
		}

		newHash, err := HashPassword(req.NewPassword)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"data": nil, "error": "Failed to hash new password"})
			return
		}

		_, err = db.Exec(`UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2`, newHash, userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"data": nil, "error": "Failed to update password"})
			return
		}

		if err := revokeAllRefreshTokens(db, userID); err != nil {
			slog.Error("refresh_token_revoke_failed", "user_id", userID, "error", err.Error())
		}

		slog.Info("password_changed", "username", username)
		c.JSON(http.StatusOK, gin.H{"data": "Password changed successfully. All sessions have been invalidated.", "error": nil})
	}
}

func PermissionsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("user_role")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"data": nil, "error": "No role assigned"})
			return
		}

		roleStr, ok := role.(string)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"data": nil, "error": "Invalid role type"})
			return
		}
		permissions := RolePermissions[roleStr]
		if permissions == nil {
			permissions = []string{}
		}

		c.JSON(http.StatusOK, gin.H{
			"data": gin.H{
				"role":        roleStr,
				"permissions": permissions,
				"level":       RoleHierarchy[roleStr],
			},
			"error": nil,
		})
	}
}

func MeHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"data": nil, "error": "Not authenticated"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": user, "error": nil})
	}
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"data": nil, "error": "Authorization header required"})
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"data": nil, "error": "Invalid authorization format"})
			c.Abort()
			return
		}

		user, err := ValidateAccessToken(parts[1])
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"data": nil, "error": "Invalid or expired token"})
			c.Abort()
			return
		}

		c.Set("user", user)
		c.Set("user_id", user.ID)
		c.Set("username", user.Username)
		c.Set("user_role", user.Role)
		c.Next()
	}
}

var RoleHierarchy = map[string]int{
	"viewer":   0,
	"auditor":  1,
	"operator": 2,
	"admin":    3,
}

func RequireRole(minRole string) gin.HandlerFunc {
	minLevel, ok := RoleHierarchy[minRole]
	if !ok {
		minLevel = RoleHierarchy["viewer"]
	}

	return func(c *gin.Context) {
		role, exists := c.Get("user_role")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"data": nil, "error": "Access denied"})
			c.Abort()
			return
		}

		userLevel, ok := RoleHierarchy[role.(string)]
		if !ok || userLevel < minLevel {
			slog.Warn("access_denied", "user_role", role, "required_role", minRole,
				"path", c.Request.URL.Path, "method", c.Request.Method)
			c.JSON(http.StatusForbidden, gin.H{"data": nil, "error": "Insufficient permissions"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func AdminOnly() gin.HandlerFunc {
	return RequireRole("admin")
}

func RequirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("user_role")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"data": nil, "error": "Access denied"})
			c.Abort()
			return
		}

		if !HasPermission(role.(string), permission) {
			slog.Warn("permission_denied", "user_role", role, "permission", permission,
				"path", c.Request.URL.Path, "method", c.Request.Method)
			c.JSON(http.StatusForbidden, gin.H{"data": nil, "error": "Insufficient permissions"})
			c.Abort()
			return
		}
		c.Next()
	}
}

var RolePermissions = map[string][]string{
	"viewer": {
		"devices:list", "devices:view",
		"scans:list", "scans:view",
		"vulnerabilities:list", "vulnerabilities:view",
		"alerts:list", "alerts:view",
		"firmware:list", "firmware:view",
		"stats:view", "kev:view",
		"safelists:list", "safelists:view",
		"webhooks:list", "webhooks:view",
		"users:list", "users:view",
		"scan-profiles:list", "scan-scopes:list",
	},
	"auditor": {
		"devices:list", "devices:view",
		"scans:list", "scans:view",
		"vulnerabilities:list", "vulnerabilities:view",
		"alerts:list", "alerts:list_all",
		"firmware:list", "firmware:view",
		"stats:view", "kev:view",
		"safelists:list",
		"webhooks:list",
		"users:list",
		"scan-profiles:list", "scan-scopes:list",
		"audit:view",
	},
	"operator": {
		"devices:list", "devices:view", "devices:scan", "devices:delete",
		"scans:list", "scans:view", "scans:create",
		"vulnerabilities:list", "vulnerabilities:view", "vulnerabilities:resolve",
		"alerts:list", "alerts:ack", "alerts:dismiss",
		"firmware:list", "firmware:view", "firmware:upload", "firmware:analyze",
		"stats:view", "kev:view",
		"safelists:list", "safelists:view", "safelists:create", "safelists:delete",
		"webhooks:list", "webhooks:view", "webhooks:create", "webhooks:delete", "webhooks:test",
		"users:list", "users:view",
		"scan-profiles:list", "scan-scopes:list", "scan-scopes:create", "scan-scopes:delete",
		"audit:view",
	},
	"admin": {
		"devices:*",
		"scans:*",
		"vulnerabilities:*",
		"alerts:*",
		"firmware:*",
		"stats:*",
		"kev:*",
		"safelists:*",
		"webhooks:*",
		"users:*",
		"scan-profiles:*",
		"scan-scopes:*",
		"audit:*",
		"admin:*",
	},
}

func HasPermission(role, permission string) bool {
	perms, ok := RolePermissions[role]
	if !ok {
		return false
	}

	for _, p := range perms {
		if p == permission {
			return true
		}
		if strings.HasSuffix(p, ":*") {
			resource := strings.TrimSuffix(p, ":*")
			if strings.HasPrefix(permission, resource+":") {
				return true
			}
		}
	}
	return false
}

func ListUsersHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		rows, err := db.Query(`SELECT id, username, email, role, is_active, last_login, created_at FROM users ORDER BY created_at DESC`)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"data": nil, "error": "Failed to query users"})
			return
		}
		defer rows.Close()

		type UserInfo struct {
			ID        string     `json:"id"`
			Username  string     `json:"username"`
			Email     string     `json:"email"`
			Role      string     `json:"role"`
			IsActive  bool       `json:"is_active"`
			LastLogin *time.Time `json:"last_login"`
			CreatedAt time.Time  `json:"created_at"`
		}

		var users []UserInfo
		for rows.Next() {
			var u UserInfo
			var lastLogin sql.NullTime
			if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.IsActive, &lastLogin, &u.CreatedAt); err != nil {
				continue
			}
			if lastLogin.Valid {
				u.LastLogin = &lastLogin.Time
			}
			users = append(users, u)
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("iterate users: %w", err)
		}
		if users == nil {
			users = []UserInfo{}
		}

		c.JSON(http.StatusOK, gin.H{"data": users, "error": nil})
	}
}
