package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/yourusername/seagles/slog"
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

var (
	keyPair     *KeyPair
	keyPairMu   sync.RWMutex
	tokenIssuer = "ironmesh"
)

func LoadOrGenerateKeys(privateKeyPEM string) error {
	mu.Lock()
	defer mu.Unlock()

	if privateKeyPEM != "" {
		block, _ := pem.Decode([]byte(privateKeyPEM))
		if block == nil || block.Type != "RSA PRIVATE KEY" {
			return errors.New("invalid RSA private key PEM")
		}
		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse RSA private key: %w", err)
		}
		keyPair = &KeyPair{
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
	keyPair = &KeyPair{
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
	}
	slog.Info("Generated new RSA key pair")
	return nil
}

func GetPublicKeyPEM() (string, error) {
	keyPairMu.RLock()
	defer keyPairMu.RUnlock()

	if keyPair == nil {
		return "", errors.New("key pair not initialized")
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(keyPair.PublicKey)
	if err != nil {
		return "", err
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

type Claims struct {
	UserID    string
	Username  string
	Role      string
	TokenID   string
	TokenType TokenType
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type SignedToken struct {
	Token  string
	Claims *Claims
}

func signRS256(claims *Claims) (string, error) {
	keyPairMu.RLock()
	priv := keyPair.PrivateKey
	keyPairMu.RUnlock()

	if priv == nil {
		return "", errors.New("key pair not initialized")
	}

	header := fmt.Sprintf(`{"alg":"RS256","typ":"JWT","kid":"ironmesh-v1"}`)
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(header))

	payload := fmt.Sprintf(`{"sub":%q,"name":%q,"role":%q,"jti":%q,"type":%q,"iat":%d,"exp":%d}`,
		claims.UserID, claims.Username, claims.Role,
		claims.TokenID, string(claims.TokenType),
		claims.IssuedAt.Unix(), claims.ExpiresAt.Unix())
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(payload))

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
	keyPairMu.RLock()
	pub := keyPair.PublicKey
	keyPairMu.RUnlock()

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
	if err := parseJSONClaims(payloadBytes, &claims); err != nil {
		return nil, err
	}

	if time.Now().After(claims.ExpiresAt) {
		return nil, errors.New("token expired")
	}

	return &claims, nil
}

func parseJSONClaims(data []byte, claims *Claims) error {
	var raw struct {
		Sub   string `json:"sub"`
		Name  string `json:"name"`
		Role  string `json:"role"`
		JTI   string `json:"jti"`
		Type  string `json:"type"`
		IAT   int64  `json:"iat"`
		Exp   int64  `json:"exp"`
	}

	if err := jsonUnmarshal(data, &raw); err != nil {
		return fmt.Errorf("failed to parse claims: %w", err)
	}

	claims.UserID = raw.Sub
	claims.Username = raw.Name
	claims.Role = raw.Role
	claims.TokenID = raw.JTI
	claims.TokenType = TokenType(raw.Type)
	claims.IssuedAt = time.Unix(raw.IAT, 0)
	claims.ExpiresAt = time.Unix(raw.Exp, 0)

	if claims.UserID == "" {
		return errors.New("missing subject claim")
	}
	if claims.TokenID == "" {
		return errors.New("missing jti claim")
	}
	if claims.TokenType == "" {
		return errors.New("missing token type claim")
	}

	return nil
}

func jsonUnmarshal(data []byte, v interface{}) error {
	stack := make([]byte, 0, len(data))
	for _, b := range data {
		if b == '\n' || b == '\r' || b == '\t' {
			continue
		}
		stack = append(stack, b)
	}

	var i int
	if err := skipWhitespace(stack, &i); err != nil {
		return err
	}
	if i >= len(stack) || stack[i] != '{' {
		return errors.New("expected {")
	}
	i++

	for i < len(stack) {
		if err := skipWhitespace(stack, &i); err != nil {
			return err
		}
		if stack[i] == '}' {
			break
		}

		var key string
		if err := parseString(stack, &i, &key); err != nil {
			return err
		}
		if err := skipWhitespace(stack, &i); err != nil {
			return err
		}
		if i >= len(stack) || stack[i] != ':' {
			return errors.New("expected :")
		}
		i++
		if err := skipWhitespace(stack, &i); err != nil {
			return err
		}

		switch key {
		case "sub":
			parseString(stack, &i, &rawField(v, "Sub"))
		case "name":
			parseString(stack, &i, &rawField(v, "Name"))
		case "role":
			parseString(stack, &i, &rawField(v, "Role"))
		case "jti":
			parseString(stack, &i, &rawField(v, "JTI"))
		case "type":
			parseString(stack, &i, &rawField(v, "Type"))
		case "iat":
			rawNum := parseInt64(stack, &i)
			*rawInt64Field(v, "IAT") = rawNum
		case "exp":
			rawNum := parseInt64(stack, &i)
			*rawInt64Field(v, "Exp") = rawNum
		default:
			skipValue(stack, &i)
		}

		if err := skipWhitespace(stack, &i); err != nil {
			return err
		}
		if stack[i] == ',' {
			i++
		}
	}

	return nil
}

func skipWhitespace(data []byte, i *int) error {
	for *i < len(data) {
		b := data[*i]
		if b == ' ' || b == '\n' || b == '\r' || b == '\t' {
			*i++
		} else {
			return nil
		}
	}
	return errors.New("unexpected end of data")
}

func parseString(data []byte, i *int, dest *string) error {
	if *i >= len(data) || data[*i] != '"' {
		return errors.New("expected \"")
	}
	*i++
	start := *i
	for *i < len(data) && data[*i] != '"' {
		if data[*i] == '\\' {
			*i += 2
		} else {
			*i++
		}
	}
	if *i >= len(data) {
		return errors.New("unterminated string")
	}
	*dest = string(data[start:*i])
	*i++
	return nil
}

func parseInt64(data []byte, i *int) int64 {
	neg := false
	if *i < len(data) && data[*i] == '-' {
		neg = true
		*i++
	}
	var n int64
	for *i < len(data) && data[*i] >= '0' && data[*i] <= '9' {
		n = n*10 + int64(data[*i]-'0')
		*i++
	}
	if neg {
		n = -n
	}
	return n
}

func skipValue(data []byte, i *int) {
	if *i >= len(data) {
		return
	}
	switch data[*i] {
	case '"':
		*i++
		for *i < len(data) && data[*i] != '"' {
			if data[*i] == '\\' {
				*i += 2
			} else {
				*i++
			}
		}
		*i++
	case '{':
		depth := 1
		*i++
		for *i < len(data) && depth > 0 {
			if data[*i] == '{' {
				depth++
			} else if data[*i] == '}' {
				depth--
			}
			*i++
		}
	case '[':
		depth := 1
		*i++
		for *i < len(data) && depth > 0 {
			if data[*i] == '[' {
				depth++
			} else if data[*i] == ']' {
				depth--
			}
			*i++
		}
	default:
		for *i < len(data) && data[*i] != ',' && data[*i] != '}' && data[*i] != ']' {
			*i++
		}
	}
}

func rawField(v interface{}, name string) *string {
	m := v.(*struct {
		Sub   string `json:"sub"`
		Name  string `json:"name"`
		Role  string `json:"role"`
		JTI   string `json:"jti"`
		Type  string `json:"type"`
		IAT   int64  `json:"iat"`
		Exp   int64  `json:"exp"`
	})
	switch name {
	case "Sub":
		return &m.Sub
	case "Name":
		return &m.Name
	case "Role":
		return &m.Role
	case "JTI":
		return &m.JTI
	case "Type":
		return &m.Type
	}
	return nil
}

func rawInt64Field(v interface{}, name string) *int64 {
	m := v.(*struct {
		Sub   string `json:"sub"`
		Name  string `json:"name"`
		Role  string `json:"role"`
		JTI   string `json:"jti"`
		Type  string `json:"type"`
		IAT   int64  `json:"iat"`
		Exp   int64  `json:"exp"`
	})
	switch name {
	case "IAT":
		return &m.IAT
	case "Exp":
		return &m.Exp
	}
	return nil
}

func generateTokenID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
