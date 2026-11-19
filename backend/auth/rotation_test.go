package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func testRSAPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}

func TestKeyRotationOverlap(t *testing.T) {
	originalActive := globalKeyPair
	originalPrevious := globalPreviousKeyPair
	t.Cleanup(func() {
		globalKeyPairMu.Lock()
		globalKeyPair = originalActive
		globalPreviousKeyPair = originalPrevious
		globalKeyPairMu.Unlock()
	})

	oldKey := testRSAPEM(t)
	newKey := testRSAPEM(t)

	if err := LoadOrGenerateKeys(newKey); err != nil {
		t.Fatalf("load active key: %v", err)
	}
	newToken, err := signRS256(&Claims{Sub: "user-1", JTI: "jti-new", TokenType: AccessToken})
	if err != nil {
		t.Fatalf("sign with active key: %v", err)
	}

	// Mint a token as if it had been issued by the retired key.
	oldPair, err := parseRSAPrivateKeyPEM(oldKey)
	if err != nil {
		t.Fatalf("parse old key: %v", err)
	}
	globalKeyPairMu.Lock()
	globalKeyPair = &KeyPair{Kid: PreviousTokenKid, PrivateKey: oldPair, PublicKey: &oldPair.PublicKey}
	globalKeyPairMu.Unlock()
	oldToken, err := signRS256(&Claims{Sub: "user-1", JTI: "jti-old", TokenType: AccessToken})
	if err != nil {
		t.Fatalf("sign with old key: %v", err)
	}
	if err := LoadOrGenerateKeys(newKey); err != nil {
		t.Fatalf("restore active key: %v", err)
	}

	if _, err := verifyRS256(oldToken); err == nil {
		t.Fatal("old token should be rejected before the previous key is loaded")
	}
	if err := LoadPreviousKey(oldKey); err != nil {
		t.Fatalf("load previous key: %v", err)
	}

	for name, token := range map[string]string{"new": newToken, "old": oldToken} {
		claims, err := verifyRS256(token)
		if err != nil {
			t.Fatalf("%s token rejected during overlap: %v", name, err)
		}
		if claims.Sub != "user-1" {
			t.Fatalf("%s token has subject %q", name, claims.Sub)
		}
	}

	keys, err := GetPublicJWKs()
	if err != nil {
		t.Fatalf("GetPublicJWKs: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("JWKS has %d keys, want 2", len(keys))
	}
	if keys[0].Kid != TokenKid || keys[1].Kid != PreviousTokenKid {
		t.Fatalf("unexpected kids: %q, %q", keys[0].Kid, keys[1].Kid)
	}

	// A kid nobody recognises must not fall back to a key that happens to verify.
	parts := strings.SplitN(newToken, ".", 3)
	unknownHeader := `{"alg":"RS256","typ":"JWT","kid":"seagles-unknown"}`
	parts[0] = base64RawURL(unknownHeader)
	if _, err := verifyRS256(strings.Join(parts, ".")); err == nil {
		t.Fatal("token with unknown kid was accepted")
	}
}

func base64RawURL(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}
