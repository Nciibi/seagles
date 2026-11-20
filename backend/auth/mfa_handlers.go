package auth

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Nciibi/seagles/slog"
)

func mfaUserID(c *gin.Context) (string, bool) {
	value, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"data": nil, "error": "Not authenticated"})
		return "", false
	}
	id, ok := value.(string)
	if !ok || id == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"data": nil, "error": "Invalid user identity"})
		return "", false
	}
	return id, true
}

// MFASetupHandler creates an unconfirmed TOTP secret. enrolment only becomes
// active after MFAEnableHandler verifies a code from the authenticator app.
func MFASetupHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !totpEncryptionConfigured() {
			c.JSON(http.StatusServiceUnavailable, gin.H{"data": nil, "error": "MFA is not configured on this server"})
			return
		}
		userID, ok := mfaUserID(c)
		if !ok {
			return
		}

		var enabled bool
		if err := db.QueryRow(`SELECT COALESCE(totp_enabled, FALSE) FROM users WHERE id = $1`, userID).Scan(&enabled); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"data": nil, "error": "Failed to read MFA status"})
			return
		}
		if enabled {
			c.JSON(http.StatusConflict, gin.H{"data": nil, "error": "MFA is already enabled"})
			return
		}

		secret, err := generateTOTPSecret()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"data": nil, "error": "Failed to generate MFA secret"})
			return
		}
		sealed, err := sealTOTPSecret(secret)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"data": nil, "error": "Failed to store MFA secret"})
			return
		}
		if _, err := db.Exec(
			`UPDATE users SET totp_secret_enc = $1, totp_enabled = FALSE WHERE id = $2`,
			sealed, userID,
		); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"data": nil, "error": "Failed to store MFA secret"})
			return
		}

		username, _ := c.Get("username")
		usernameStr, _ := username.(string)
		c.JSON(http.StatusOK, gin.H{
			"data": MFASetupResponse{
				Secret:     mfaBase32.EncodeToString(secret),
				OTPAuthURI: totpURI(secret, usernameStr, "Seagles"),
				Enabled:    false,
			},
			"error": nil,
		})
	}
}

// MFAStatusHandler lets the UI show whether MFA is active without exposing
// the secret.
func MFAStatusHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := mfaUserID(c)
		if !ok {
			return
		}
		var enabled bool
		if err := db.QueryRow(`SELECT COALESCE(totp_enabled, FALSE) FROM users WHERE id = $1`, userID).Scan(&enabled); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"data": nil, "error": "Failed to read MFA status"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"data":  gin.H{"enabled": enabled, "configured": totpEncryptionConfigured()},
			"error": nil,
		})
	}
}

func loadMFASecret(db *sql.DB, userID string) ([]byte, error) {
	var sealed []byte
	if err := db.QueryRow(`SELECT totp_secret_enc FROM users WHERE id = $1`, userID).Scan(&sealed); err != nil {
		return nil, err
	}
	if len(sealed) == 0 {
		return nil, errors.New("MFA setup not started")
	}
	return openTOTPSecret(sealed)
}

// MFAEnableHandler activates MFA only after a valid code proves enrolment.
func MFAEnableHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req MFACodeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"data": nil, "error": "A 6-digit code is required"})
			return
		}
		userID, ok := mfaUserID(c)
		if !ok {
			return
		}
		secret, err := loadMFASecret(db, userID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"data": nil, "error": "MFA setup not started"})
			return
		}
		if !verifyTOTPCode(secret, req.Code, time.Now()) {
			slog.Warn("mfa_enable_failed", "user_id", userID)
			c.JSON(http.StatusForbidden, gin.H{"data": nil, "error": "Invalid verification code"})
			return
		}
		if _, err := db.Exec(`UPDATE users SET totp_enabled = TRUE WHERE id = $1`, userID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"data": nil, "error": "Failed to enable MFA"})
			return
		}
		slog.Info("mfa_enabled", "user_id", userID)
		c.JSON(http.StatusOK, gin.H{"data": "MFA enabled", "error": nil})
	}
}

// MFADisableHandler requires a current code so a stolen session alone cannot
// silently downgrade the account.
func MFADisableHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req MFACodeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"data": nil, "error": "A 6-digit code is required"})
			return
		}
		userID, ok := mfaUserID(c)
		if !ok {
			return
		}
		secret, err := loadMFASecret(db, userID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"data": nil, "error": "MFA is not enrolled"})
			return
		}
		if !verifyTOTPCode(secret, req.Code, time.Now()) {
			slog.Warn("mfa_disable_failed", "user_id", userID)
			c.JSON(http.StatusForbidden, gin.H{"data": nil, "error": "Invalid verification code"})
			return
		}
		if _, err := db.Exec(
			`UPDATE users SET totp_enabled = FALSE, totp_secret_enc = NULL WHERE id = $1`, userID,
		); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"data": nil, "error": "Failed to disable MFA"})
			return
		}
		slog.Info("mfa_disabled", "user_id", userID)
		c.JSON(http.StatusOK, gin.H{"data": "MFA disabled", "error": nil})
	}
}

// MFAVerifyHandler completes login for MFA-enabled accounts. It exchanges a
// short-lived challenge token plus a TOTP code for the normal token pair.
func MFAVerifyHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req MFAVerifyRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"data": nil, "error": "MFA token and a 6-digit code are required"})
			return
		}
		user, err := ValidateMFAToken(req.MFAToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"data": nil, "error": "Invalid or expired MFA challenge"})
			return
		}

		var sealed []byte
		var active bool
		err = db.QueryRow(
			`SELECT totp_secret_enc, is_active FROM users
			 WHERE id = $1 AND COALESCE(tenant_id, $2) = $2`,
			user.ID, user.TenantID,
		).Scan(&sealed, &active)
		if err != nil || !active || len(sealed) == 0 {
			c.JSON(http.StatusUnauthorized, gin.H{"data": nil, "error": "Invalid or expired MFA challenge"})
			return
		}
		secret, err := openTOTPSecret(sealed)
		if err != nil || !verifyTOTPCode(secret, req.Code, time.Now()) {
			slog.Warn("mfa_verify_failed", "user_id", user.ID)
			c.JSON(http.StatusUnauthorized, gin.H{"data": nil, "error": "Invalid verification code"})
			return
		}

		accessToken, err := GenerateAccessToken(*user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"data": nil, "error": "Failed to generate token"})
			return
		}
		refreshTokenID := generateTokenID()
		refreshExpiry := time.Now().Add(RefreshTokenTTL)
		if err := storeRefreshToken(db, user.ID, user.TenantID, refreshTokenID, refreshExpiry); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"data": nil, "error": "Failed to generate refresh token"})
			return
		}

		slog.Info("mfa_verify_success", "user_id", user.ID)
		c.JSON(http.StatusOK, gin.H{
			"data": LoginResponse{
				Token:        accessToken.Token,
				ExpiresIn:    int64(time.Until(time.Unix(accessToken.Claims.Exp, 0)).Seconds()),
				RefreshToken: refreshTokenID + "." + user.ID,
				User:         *user,
			},
			"error": nil,
		})
	}
}
