package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/Nciibi/seagles/cache"
	"github.com/Nciibi/seagles/slog"
)

type TokenType string

const (
	AccessToken  TokenType = "access"
	RefreshToken TokenType = "refresh"

	AccessTokenTTL  = 15 * time.Minute
	RefreshTokenTTL = 7 * 24 * time.Hour

	TokenIssuer   = "seagles"
	TokenAudience = "seagles-api"
	TokenKid      = "seagles-v1"

	// PreviousTokenKid identifies the retired signing key during a rotation
	// window. Tokens signed with it remain verifiable until the overlap ends.
	PreviousTokenKid = "seagles-previous"

	// DefaultTenantID is the tenant every existing row was backfilled to by
	// migration 015. Single-tenant deployments continue to use it.
	DefaultTenantID = "00000000-0000-0000-0000-000000000001"
)

type KeyPair struct {
	Kid        string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

type Claims struct {
	Sub       string    `json:"sub"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	JTI       string    `json:"jti"`
	TenantID  string    `json:"tenant_id,omitempty"`
	Iss       string    `json:"iss"`
	Aud       string    `json:"aud"`
	TokenType TokenType `json:"type"`
	IAT       int64     `json:"iat"`
	Exp       int64     `json:"exp"`
	// MustChangePassword is copied from the User so RequirePasswordChange can
	// gate endpoints without a database round trip.
	MustChangePassword bool `json:"mcp,omitempty"`
}

type SignedToken struct {
	Token  string
	Claims *Claims
}

var (
	globalKeyPair   *KeyPair
	globalKeyPairMu sync.RWMutex

	// globalPreviousKeyPair holds the retired key during a rotation window so
	// tokens minted before the switch keep working until they expire.
	globalPreviousKeyPair *KeyPair

	// keyIsEphemeral records that the active key pair was generated in-process
	// rather than loaded from configuration. See UsingEphemeralKey.
	keyIsEphemeral bool
)

// parseRSAPrivateKeyPEM accepts both private-key encodings that are in real
// use:
//
//   - PKCS#1, "-----BEGIN RSA PRIVATE KEY-----", which is what
//     `openssl genrsa -traditional` and Go's x509.MarshalPKCS1PrivateKey emit.
//   - PKCS#8, "-----BEGIN PRIVATE KEY-----", which is what OpenSSL 3.x emits
//     by default for `openssl genrsa` and `openssl genpkey`.
//
// Only PKCS#1 was accepted before, so the documented setup command
// (`openssl genrsa 2048`) produced a key the server rejected with
// "invalid RSA private key PEM" on OpenSSL 3.x.
func parseRSAPrivateKeyPEM(privateKeyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errors.New("invalid RSA private key PEM: no PEM block found")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#1 RSA private key: %w", err)
		}
		return priv, nil
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
		priv, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 private key is %T, want an RSA key; "+
				"generate one with: openssl genrsa 2048", parsed)
		}
		return priv, nil
	case "EC PRIVATE KEY", "DSA PRIVATE KEY":
		return nil, fmt.Errorf("PEM block type %q is not an RSA key; "+
			"generate one with: openssl genrsa 2048", block.Type)
	case "ENCRYPTED PRIVATE KEY":
		return nil, errors.New("private key is encrypted; decrypt it first, e.g. " +
			"openssl pkcs8 -in key.pem -out key-decrypted.pem")
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q, want "+
			"\"RSA PRIVATE KEY\" (PKCS#1) or \"PRIVATE KEY\" (PKCS#8)", block.Type)
	}
}

// UsingEphemeralKey reports whether the signing key was auto-generated instead
// of loaded from JWT_SECRET / JWT_PRIVATE_KEY_FILE.
//
// An ephemeral key is fine for a single local process, but it is invalid for
// any deployment running more than one instance: every instance generates its
// own key, so a token minted by one instance fails signature verification on
// the others, users see intermittent 401s, and every rollout invalidates all
// sessions. main() uses this to fail fast instead.
func UsingEphemeralKey() bool {
	globalKeyPairMu.RLock()
	defer globalKeyPairMu.RUnlock()
	return keyIsEphemeral
}

func LoadOrGenerateKeys(privateKeyPEM string) error {
	globalKeyPairMu.Lock()
	defer globalKeyPairMu.Unlock()

	if privateKeyPEM != "" {
		priv, err := parseRSAPrivateKeyPEM(privateKeyPEM)
		if err != nil {
			return err
		}
		globalKeyPair = &KeyPair{
			Kid:        TokenKid,
			PrivateKey: priv,
			PublicKey:  &priv.PublicKey,
		}
		// A fresh active key invalidates any rotation window that was open.
		globalPreviousKeyPair = nil
		keyIsEphemeral = false
		slog.Info("Loaded existing RSA key pair")
		return nil
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}
	globalKeyPair = &KeyPair{
		Kid:        TokenKid,
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
	}
	globalPreviousKeyPair = nil
	keyIsEphemeral = true
	slog.Warn("Generated an ephemeral RSA key pair: it is NOT shared with any " +
		"other instance and is lost on restart. This is only safe for a single " +
		"local process. Set JWT_SECRET (RSA private key PEM) or " +
		"JWT_PRIVATE_KEY_FILE for any multi-replica deployment.")
	return nil
}

// LoadPreviousKey registers the retired signing key for the overlap window.
// It must be called after LoadOrGenerateKeys so a rotation publishes the new
// key as active while still verifying tokens issued by the old one.
func LoadPreviousKey(privateKeyPEM string) error {
	if strings.TrimSpace(privateKeyPEM) == "" {
		return nil
	}
	priv, err := parseRSAPrivateKeyPEM(privateKeyPEM)
	if err != nil {
		return fmt.Errorf("previous JWT signing key: %w", err)
	}

	globalKeyPairMu.Lock()
	defer globalKeyPairMu.Unlock()
	globalPreviousKeyPair = &KeyPair{
		Kid:        PreviousTokenKid,
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
	}
	slog.Info("Previous JWT signing key loaded for rotation overlap", "kid", PreviousTokenKid)
	return nil
}

// JWK is the public portion of the active signing key in RFC 7517 form.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// GetPublicJWK returns the active RSA public key for external token
// verification. Only the modulus and exponent are exposed.
func GetPublicJWK() (JWK, error) {
	globalKeyPairMu.RLock()
	pair := globalKeyPair
	var pub *rsa.PublicKey
	if pair != nil {
		pub = pair.PublicKey
	}
	globalKeyPairMu.RUnlock()

	if pub == nil {
		return JWK{}, errors.New("key pair not initialized")
	}

	kid := TokenKid
	if pair != nil && pair.Kid != "" {
		kid = pair.Kid
	}
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}, nil
}

// GetPublicJWKs publishes every key currently accepted for verification.
// During a rotation both the new and the retired key are present; consumers
// select by "kid" and can switch keys without a verification outage.
func GetPublicJWKs() ([]JWK, error) {
	active, err := GetPublicJWK()
	if err != nil {
		return nil, err
	}
	keys := []JWK{active}

	globalKeyPairMu.RLock()
	previous := globalPreviousKeyPair
	globalKeyPairMu.RUnlock()
	if previous == nil || previous.PublicKey == nil {
		return keys, nil
	}
	keys = append(keys, JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: PreviousTokenKid,
		N:   base64.RawURLEncoding.EncodeToString(previous.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(previous.PublicKey.E)).Bytes()),
	})
	return keys, nil
}

func GetPublicKeyPEM() (string, error) {
	globalKeyPairMu.RLock()
	defer globalKeyPairMu.RUnlock()

	if globalKeyPair == nil {
		return "", errors.New("key pair not initialized")
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(globalKeyPair.PublicKey)
	if err != nil {
		return "", err
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

func signRS256(claims *Claims) (string, error) {
	globalKeyPairMu.RLock()
	pair := globalKeyPair
	var priv *rsa.PrivateKey
	kid := TokenKid
	if pair != nil {
		priv = pair.PrivateKey
		if pair.Kid != "" {
			kid = pair.Kid
		}
	}
	globalKeyPairMu.RUnlock()

	if priv == nil {
		return "", errors.New("key pair not initialized")
	}

	// Stamp issuer and audience at signing time so no caller can mint a token
	// that claims to come from another issuer.
	if claims.Iss == "" {
		claims.Iss = TokenIssuer
	}
	if claims.Aud == "" {
		claims.Aud = TokenAudience
	}

	header := `{"alg":"RS256","typ":"JWT","kid":"` + kid + `"}`
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(header))

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)

	signingInput := headerB64 + "." + payloadB64
	hashed := sha256.Sum256([]byte(signingInput))

	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + sigB64, nil
}

func verifyRS256(tokenStr string) (*Claims, error) {
	globalKeyPairMu.RLock()
	pair := globalKeyPair
	var pub *rsa.PublicKey
	if pair != nil {
		pub = pair.PublicKey
	}
	globalKeyPairMu.RUnlock()

	if pub == nil {
		return nil, errors.New("key pair not initialized")
	}

	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	signingInput := parts[0] + "." + parts[1]
	hashed := sha256.Sum256([]byte(signingInput))

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("invalid token signature encoding")
	}

	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], sig); err != nil {
		return nil, errors.New("invalid token signature")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid token payload encoding")
	}

	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	if claims.Sub == "" {
		return nil, errors.New("missing subject claim")
	}
	if claims.JTI == "" {
		return nil, errors.New("missing jti claim")
	}
	if claims.TokenType == "" {
		return nil, errors.New("missing token type claim")
	}
	if claims.Iss != TokenIssuer {
		return nil, errors.New("invalid token issuer")
	}
	if claims.Aud != TokenAudience {
		return nil, errors.New("invalid token audience")
	}

	if time.Now().After(time.Unix(claims.Exp, 0)) {
		return nil, errors.New("token expired")
	}

	return &claims, nil
}

func GenerateAccessToken(user User) (*SignedToken, error) {
	tokenID := generateTokenID()
	now := time.Now()
	exp := now.Add(AccessTokenTTL)

	claims := &Claims{
		Sub:                user.ID,
		Name:               user.Username,
		Role:               user.Role,
		JTI:                tokenID,
		TenantID:           tenantIDForUser(user),
		Iss:                TokenIssuer,
		Aud:                TokenAudience,
		TokenType:          AccessToken,
		IAT:                now.Unix(),
		Exp:                exp.Unix(),
		MustChangePassword: user.MustChangePassword,
	}

	token, err := signRS256(claims)
	if err != nil {
		return nil, err
	}

	return &SignedToken{
		Token:  token,
		Claims: claims,
	}, nil
}

func ValidateAccessToken(tokenStr string) (*User, error) {
	claims, err := verifyRS256(tokenStr)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != AccessToken {
		return nil, errors.New("not an access token")
	}

	if cache.IsTokenBlacklisted(claims.JTI) {
		return nil, errors.New("token has been revoked")
	}

	return &User{
		ID:                 claims.Sub,
		Username:           claims.Name,
		Role:               claims.Role,
		TokenID:            claims.JTI,
		TenantID:           tenantIDForClaim(claims.TenantID),
		MustChangePassword: claims.MustChangePassword,
	}, nil
}

func tenantIDForUser(user User) string {
	if user.TenantID != "" {
		return user.TenantID
	}
	return DefaultTenantID
}

func tenantIDForClaim(tenantID string) string {
	if tenantID != "" {
		return tenantID
	}
	return DefaultTenantID
}

func generateTokenID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
