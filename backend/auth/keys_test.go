package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return key
}

func pkcs1PEM(t *testing.T) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(mustRSAKey(t)),
	}))
}

func pkcs8PEM(t *testing.T) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(mustRSAKey(t))
	if err != nil {
		t.Fatalf("failed to marshal PKCS#8: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}))
}

// PKCS#1: "openssl genrsa -traditional 2048" and Go's
// x509.MarshalPKCS1PrivateKey.
func TestParseRSAPrivateKeyPEM_PKCS1(t *testing.T) {
	key, err := parseRSAPrivateKeyPEM(pkcs1PEM(t))
	if err != nil {
		t.Fatalf("PKCS#1 key rejected: %v", err)
	}
	if key.N.BitLen() != 2048 {
		t.Errorf("key size = %d bits, want 2048", key.N.BitLen())
	}
}

// PKCS#8: the DEFAULT output of `openssl genrsa 2048` on OpenSSL 3.x, which is
// the command the setup docs tell operators to run. Only PKCS#1 was accepted
// before, so the documented setup produced a key the server rejected with
// "invalid RSA private key PEM".
func TestParseRSAPrivateKeyPEM_PKCS8(t *testing.T) {
	key, err := parseRSAPrivateKeyPEM(pkcs8PEM(t))
	if err != nil {
		t.Fatalf("PKCS#8 key rejected: %v", err)
	}
	if key.N.BitLen() != 2048 {
		t.Errorf("key size = %d bits, want 2048", key.N.BitLen())
	}
}

func TestParseRSAPrivateKeyPEM_RejectsGarbage(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantSub string
	}{
		{"empty", "", "no PEM block found"},
		{"not PEM at all", "just a string", "no PEM block found"},
		{"truncated PKCS#1", "-----BEGIN RSA PRIVATE KEY-----\nZm9v\n", "PKCS#1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseRSAPrivateKeyPEM(tc.input)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not mention %q", err, tc.wantSub)
			}
		})
	}
}

func TestParseRSAPrivateKeyPEM_RejectsECKeyWithGuidance(t *testing.T) {
	ecDER, err := x509.MarshalECPrivateKey(generateECKey(t))
	if err != nil {
		t.Fatalf("failed to marshal EC key: %v", err)
	}
	ecPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}))

	_, err = parseRSAPrivateKeyPEM(ecPEM)
	if err == nil {
		t.Fatal("expected an error for an EC key")
	}
	if !strings.Contains(err.Error(), "want an RSA key") {
		t.Errorf("error should explain that an RSA key is required, got: %v", err)
	}
}

func TestParseRSAPrivateKeyPEM_RejectsEncryptedWithGuidance(t *testing.T) {
	encPEM := "-----BEGIN ENCRYPTED PRIVATE KEY-----\nZm9v\n-----END ENCRYPTED PRIVATE KEY-----\n"
	_, err := parseRSAPrivateKeyPEM(encPEM)
	if err == nil {
		t.Fatal("expected an error for an encrypted key")
	}
	if !strings.Contains(err.Error(), "openssl pkcs8") {
		t.Errorf("error should tell the operator how to decrypt, got: %v", err)
	}
}

// A key loaded from configuration must actually sign verifiable tokens, and
// must not be reported as ephemeral.
func TestLoadedKeySignsAndVerifies(t *testing.T) {
	original := globalKeyPair
	originalEphemeral := keyIsEphemeral
	t.Cleanup(func() {
		globalKeyPairMu.Lock()
		globalKeyPair = original
		keyIsEphemeral = originalEphemeral
		globalKeyPairMu.Unlock()
	})

	if err := LoadOrGenerateKeys(pkcs8PEM(t)); err != nil {
		t.Fatalf("failed to load PKCS#8 key: %v", err)
	}
	if UsingEphemeralKey() {
		t.Error("UsingEphemeralKey() = true after loading a key")
	}

	signed, err := signRS256(&Claims{
		Sub:       "user-1",
		Name:      "operator",
		Role:      "admin",
		JTI:       "jti-1",
		TokenType: AccessToken,
		Exp:       4102444800, // 2100-01-01
	})
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	// ValidateAccessToken returns the principal built from the claims.
	user, err := ValidateAccessToken(signed)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}
	if user.Username != "user-1" {
		t.Errorf("username = %q, want user-1", user.Username)
	}
	if user.Role != "admin" {
		t.Errorf("role = %q, want admin", user.Role)
	}
	if user.TokenID != "jti-1" {
		t.Errorf("token id = %q, want jti-1", user.TokenID)
	}
}

// A token signed by one ephemeral key must be rejected by another instance,
// which is exactly the multi-replica failure REQUIRE_SHARED_JWT_KEY prevents.
func TestEphemeralKeysAreNotInterchangeable(t *testing.T) {
	original := globalKeyPair
	originalEphemeral := keyIsEphemeral
	t.Cleanup(func() {
		globalKeyPairMu.Lock()
		globalKeyPair = original
		keyIsEphemeral = originalEphemeral
		globalKeyPairMu.Unlock()
	})

	if err := LoadOrGenerateKeys(""); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	signed, err := signRS256(&Claims{
		Sub: "user-1", JTI: "jti-1", TokenType: AccessToken, Exp: 4102444800,
	})
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	if _, err := ValidateAccessToken(signed); err != nil {
		t.Fatalf("token should validate on the issuing instance: %v", err)
	}

	// Simulate a second replica starting with its own generated key.
	if err := LoadOrGenerateKeys(""); err != nil {
		t.Fatalf("failed to generate second key: %v", err)
	}
	if _, err := ValidateAccessToken(signed); err == nil {
		t.Error("token from another instance validated; ephemeral keys must not " +
			"be interchangeable (this is what REQUIRE_SHARED_JWT_KEY prevents)")
	}
}

func generateECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}
	return key
}
