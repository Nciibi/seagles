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
}

type SignedToken struct {
	Token  string
	Claims *Claims
}

var (
	globalKeyPair   *KeyPair
	globalKeyPairMu sync.RWMutex
	tokenIssuer     = "seagles"
)

func LoadOrGenerateKeys(privateKeyPEM string) error {
	globalKeyPairMu.Lock()
	defer globalKeyPairMu.Unlock()

	if privateKeyPEM != "" {
		block, _ := pem.Decode([]byte(privateKeyPEM))
		if block == nil || block.Type != "RSA PRIVATE KEY" {
			return errors.New("invalid RSA private key PEM")
		}
		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse RSA private key: %w", err)
		}
		globalKeyPair = &KeyPair{
			PrivateKey: priv,
			PublicKey:  &priv.PublicKey,
		}
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
	slog.Info("Generated new RSA key pair")
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
		ID:       claims.Sub,
		Username: claims.Name,
		Role:     claims.Role,
		TokenID:  claims.JTI,
	}, nil
}

func generateTokenID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
