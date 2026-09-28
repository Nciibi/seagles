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
)

type KeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

type Claims struct {
	Sub       string    `json:"sub"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	JTI       string    `json:"jti"`
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
	tokenIssuer     = "seagles"

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
			PrivateKey: priv,
			PublicKey:  &priv.PublicKey,
		}
		keyIsEphemeral = false
		slog.Info("Loaded existing RSA key pair")
		return nil
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}
	globalKeyPair = &KeyPair{
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
	}
	keyIsEphemeral = true
	slog.Warn("Generated an ephemeral RSA key pair: it is NOT shared with any " +
		"other instance and is lost on restart. This is only safe for a single " +
		"local process. Set JWT_SECRET (RSA private key PEM) or " +
		"JWT_PRIVATE_KEY_FILE for any multi-replica deployment.")
	return nil
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
	priv := globalKeyPair.PrivateKey
	globalKeyPairMu.RUnlock()

	if priv == nil {
		return "", errors.New("key pair not initialized")
	}

	header := `{"alg":"RS256","typ":"JWT","kid":"seagles-v1"}`
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
	pub := globalKeyPair.PublicKey
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
		Sub:       user.ID,
		Name:      user.Username,
		Role:      user.Role,
		JTI:       tokenID,
		TokenType: AccessToken,
		IAT:       now.Unix(),
		Exp:       exp.Unix(),
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
		MustChangePassword: claims.MustChangePassword,
	}, nil
}

func generateTokenID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
