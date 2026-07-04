package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/seagles/slog"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret []byte

func init() {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		slog.Fatal("Failed to generate JWT secret")
	}
	jwtSecret = secret
}

func SetJWTSecret(secret string) {
	if secret != "" {
		jwtSecret = []byte(secret)
	}
}

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
	Token     string `json:"token"`
	ExpiresIn int64  `json:"expires_in"`
	User      User   `json:"user"`
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50,alphanum"`
	Email    string `json:"email" binding:"required,email,max=255"`
	Password string `json:"password" binding:"required,min=8,max=128"`
	Role     string `json:"role" binding:"omitempty,oneof=admin viewer"`
}

func hmacSign(data string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

func generateTokenID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

func CheckPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func GenerateToken(user User) (string, time.Time) {
	tokenID := generateTokenID()
	expiresAt := time.Now().Add(24 * time.Hour)

	tokenPayload := strings.Join([]string{
		user.ID, user.Username, user.Role, tokenID,
		expiresAt.Format(time.RFC3339),
	}, "|")

	sig := hmacSign(tokenPayload, jwtSecret)
	token := hex.EncodeToString([]byte(tokenPayload)) + "." + sig
	return token, expiresAt
}

func ValidateToken(tokenStr string) (*User, error) {
	parts := strings.SplitN(tokenStr, ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("invalid token format")
	}

	payloadBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("invalid token encoding")
	}
	payload := string(payloadBytes)

	expectedSig := hmacSign(payload, jwtSecret)
	if !hmac.Equal([]byte(parts[1]), []byte(expectedSig)) {
		return nil, errors.New("invalid token signature")
	}

	fields := strings.Split(payload, "|")
	if len(fields) != 5 {
		return nil, errors.New("invalid token payload")
	}

	expiry, err := time.Parse(time.RFC3339, fields[4])
	if err != nil {
		return nil, errors.New("invalid token expiry")
	}

	if time.Now().After(expiry) {
		return nil, errors.New("token expired")
	}

	return &User{
		ID:       fields[0],
		Username: fields[1],
		Role:     fields[2],
	}, nil
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

		token, expiresAt := GenerateToken(user)
		slog.Info("login_success", "username", user.Username, "role", user.Role)

		c.JSON(http.StatusOK, gin.H{
			"data": LoginResponse{
				Token:     token,
				ExpiresIn: int64(time.Until(expiresAt).Seconds()),
				User:      user,
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
		if req.Role == "admin" {
			role = "admin"
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

		user, err := ValidateToken(parts[1])
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"data": nil, "error": "Invalid or expired token"})
			c.Abort()
			return
		}

		c.Set("user", user)
		c.Set("user_id", user.ID)
		c.Set("user_role", user.Role)
		c.Next()
	}
}

func AdminOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("user_role")
		if !exists || role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"data": nil, "error": "Admin access required"})
			c.Abort()
			return
		}
		c.Next()
	}
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
		if users == nil {
			users = []UserInfo{}
		}

		c.JSON(http.StatusOK, gin.H{"data": users, "error": nil})
	}
}
