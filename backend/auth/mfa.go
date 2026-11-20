package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"
)

const (
	mfaSecretBytes = 20
	mfaStepSeconds = 30
	mfaDigits      = 6
	mfaSkew        = 1
)

var (
	mfaKeyMu sync.RWMutex
	mfaKey   []byte
)

var mfaBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// SetTOTPEncryptionKey installs the AES-256 key used to seal TOTP secrets.
// An empty key disables enrolment (MFA handlers fail closed).
func SetTOTPEncryptionKey(encoded string) error {
	if encoded == "" {
		mfaKeyMu.Lock()
		mfaKey = nil
		mfaKeyMu.Unlock()
		return nil
	}
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("TOTP_ENCRYPTION_KEY must be base64: %w", err)
	}
	if len(key) != 32 {
		return fmt.Errorf("TOTP_ENCRYPTION_KEY must decode to 32 bytes, got %d", len(key))
	}
	mfaKeyMu.Lock()
	mfaKey = key
	mfaKeyMu.Unlock()
	return nil
}

func totpEncryptionConfigured() bool {
	mfaKeyMu.RLock()
	defer mfaKeyMu.RUnlock()
	return len(mfaKey) == 32
}

// sealTOTPSecret encrypts a shared secret with AES-256-GCM. The random nonce
// is prepended to the ciphertext so each encryption of the same secret differs.
func sealTOTPSecret(secret []byte) ([]byte, error) {
	mfaKeyMu.RLock()
	key := mfaKey
	mfaKeyMu.RUnlock()
	if len(key) != 32 {
		return nil, errors.New("TOTP encryption key not configured")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, secret, nil), nil
}

func openTOTPSecret(sealed []byte) ([]byte, error) {
	mfaKeyMu.RLock()
	key := mfaKey
	mfaKeyMu.RUnlock()
	if len(key) != 32 {
		return nil, errors.New("TOTP encryption key not configured")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < aead.NonceSize() {
		return nil, errors.New("invalid sealed TOTP secret")
	}
	nonce, ciphertext := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	return aead.Open(nil, nonce, ciphertext, nil)
}

func generateTOTPSecret() ([]byte, error) {
	secret := make([]byte, mfaSecretBytes)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	return secret, nil
}

func totpURI(secret []byte, username, issuer string) string {
	label := url.QueryEscape(issuer + ":" + username)
	query := url.Values{}
	query.Set("secret", mfaBase32.EncodeToString(secret))
	query.Set("issuer", issuer)
	query.Set("algorithm", "SHA1")
	query.Set("digits", "6")
	query.Set("period", "30")
	return "otpauth://totp/" + label + "?" + query.Encode()
}

// totpCodeAt implements RFC 6238 with HMAC-SHA1, 30-second steps and 6 digits.
func totpCodeAt(secret []byte, at time.Time) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(at.Unix()/mfaStepSeconds))
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	return fmt.Sprintf("%06d", bin%1000000)
}

// verifyTOTPCode accepts the current step plus one step of clock skew either
// way. Codes are fixed-width numeric strings, compared in constant time.
func verifyTOTPCode(secret []byte, code string, at time.Time) bool {
	if len(code) != mfaDigits {
		return false
	}
	for _, ch := range code {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	for skew := -mfaSkew; skew <= mfaSkew; skew++ {
		atSkew := at.Add(time.Duration(skew*mfaStepSeconds) * time.Second)
		if hmac.Equal([]byte(totpCodeAt(secret, atSkew)), []byte(code)) {
			return true
		}
	}
	return false
}

// GenerateMFAToken mints a short-lived, single-purpose token that proves the
// password factor was satisfied. It cannot access any API endpoint.
func GenerateMFAToken(user User) (*SignedToken, error) {
	now := time.Now()
	claims := &Claims{
		Sub:       user.ID,
		Name:      user.Username,
		Role:      user.Role,
		JTI:       generateTokenID(),
		TenantID:  tenantIDForUser(user),
		Iss:       TokenIssuer,
		Aud:       TokenAudience,
		TokenType: MFAToken,
		IAT:       now.Unix(),
		Exp:       now.Add(MFATTLS).Unix(),
	}
	token, err := signRS256(claims)
	if err != nil {
		return nil, err
	}
	return &SignedToken{Token: token, Claims: claims}, nil
}

func ValidateMFAToken(tokenStr string) (*User, error) {
	claims, err := verifyRS256(tokenStr)
	if err != nil {
		return nil, err
	}
	if claims.TokenType != MFAToken {
		return nil, errors.New("invalid token type for MFA verification")
	}
	return &User{
		ID:                 claims.Sub,
		Username:           claims.Name,
		Role:               claims.Role,
		TenantID:           tenantIDForClaim(claims.TenantID),
		MustChangePassword: claims.MustChangePassword,
	}, nil
}
