package auth

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func withTestKeys(t *testing.T) {
	t.Helper()
	original := globalKeyPair
	t.Cleanup(func() {
		globalKeyPairMu.Lock()
		globalKeyPair = original
		globalKeyPairMu.Unlock()
	})
	if err := LoadOrGenerateKeys(""); err != nil {
		t.Fatalf("load keys: %v", err)
	}
}

func TestJWKSHandlerPublishesActiveKey(t *testing.T) {
	withTestKeys(t)
	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/auth/jwks.json", nil)
	JWKSHandler()(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Keys []JWK `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body.Keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(body.Keys))
	}
	jwk := body.Keys[0]
	if jwk.Kty != "RSA" || jwk.Alg != "RS256" || jwk.Use != "sig" || jwk.Kid != TokenKid {
		t.Fatalf("unexpected JWK header: %+v", jwk)
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		t.Fatalf("decode modulus: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		t.Fatalf("decode exponent: %v", err)
	}

	globalKeyPairMu.RLock()
	pub := globalKeyPair.PublicKey
	n, e := pub.N, pub.E
	globalKeyPairMu.RUnlock()

	if new(big.Int).SetBytes(nBytes).Cmp(n) != 0 {
		t.Fatal("JWK modulus does not match signing key")
	}
	if int(new(big.Int).SetBytes(eBytes).Int64()) != e {
		t.Fatal("JWK exponent does not match signing key")
	}
}

func TestClaimsCarryIssuerAndAudience(t *testing.T) {
	withTestKeys(t)
	token, err := GenerateAccessToken(User{ID: "u1", Username: "admin", Role: "admin"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if token.Claims.Iss != TokenIssuer || token.Claims.Aud != TokenAudience {
		t.Fatalf("claims iss/aud = %q/%q", token.Claims.Iss, token.Claims.Aud)
	}
	if token.Claims.TenantID != DefaultTenantID {
		t.Fatalf("claims tenant = %q, want %q", token.Claims.TenantID, DefaultTenantID)
	}
	user, err := ValidateAccessToken(token.Token)
	if err != nil {
		t.Fatalf("validate own token: %v", err)
	}
	if user.TenantID != DefaultTenantID {
		t.Fatalf("validated tenant = %q, want %q", user.TenantID, DefaultTenantID)
	}
}

func TestVerifyRejectsForeignIssuerOrAudience(t *testing.T) {
	withTestKeys(t)

	for _, tc := range []struct {
		name string
		iss  string
		aud  string
		want string
	}{
		{"issuer", "other-issuer", TokenAudience, "invalid token issuer"},
		{"audience", TokenIssuer, "other-api", "invalid token audience"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := &Claims{
				Sub: "u1", JTI: "j1", TokenType: AccessToken,
				Iss: tc.iss, Aud: tc.aud,
				Exp: time.Now().Add(time.Hour).Unix(),
			}
			signed, err := signRS256(claims)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			_, err = verifyRS256(signed)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("verify error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestNilKeyPairIsRejected(t *testing.T) {
	original := globalKeyPair
	t.Cleanup(func() {
		globalKeyPairMu.Lock()
		globalKeyPair = original
		globalKeyPairMu.Unlock()
	})
	globalKeyPairMu.Lock()
	globalKeyPair = nil
	globalKeyPairMu.Unlock()

	if _, err := signRS256(&Claims{}); err == nil {
		t.Fatal("signRS256 accepted a nil key pair")
	}
	if _, err := verifyRS256("a.b.c"); err == nil {
		t.Fatal("verifyRS256 accepted a nil key pair")
	}
	if _, err := GetPublicJWK(); err == nil {
		t.Fatal("GetPublicJWK accepted a nil key pair")
	}
	if _, err := GetPublicKeyPEM(); err == nil {
		t.Fatal("GetPublicKeyPEM accepted a nil key pair")
	}
}
