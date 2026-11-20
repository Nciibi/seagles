package auth

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	"github.com/Nciibi/seagles/cache"
)

func TestSetTOTPEncryptionKey(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	if err := SetTOTPEncryptionKey(valid); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	if !totpEncryptionConfigured() {
		t.Fatal("key should be configured")
	}
	if err := SetTOTPEncryptionKey("not base64!"); err == nil {
		t.Fatal("invalid base64 key accepted")
	}
	if err := SetTOTPEncryptionKey(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Fatal("short key accepted")
	}
	if err := SetTOTPEncryptionKey(""); err != nil {
		t.Fatalf("empty key should disable MFA: %v", err)
	}
	if totpEncryptionConfigured() {
		t.Fatal("MFA should be disabled with an empty key")
	}
}

func TestTOTPSecretRoundTrip(t *testing.T) {
	if err := SetTOTPEncryptionKey(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))); err != nil {
		t.Fatal(err)
	}
	defer SetTOTPEncryptionKey("")

	secret, err := generateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealTOTPSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sealed, secret) {
		t.Fatal("sealed secret must not equal plaintext")
	}
	opened, err := openTOTPSecret(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, secret) {
		t.Fatal("round trip changed the secret")
	}
	second, err := sealTOTPSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sealed, second) {
		t.Fatal("GCM sealing must use a fresh nonce")
	}
}

func TestTOTPReferenceVector(t *testing.T) {
	secret := []byte("12345678901234567890")
	if got := totpCodeAt(secret, time.Unix(59, 0)); got != "287082" {
		t.Fatalf("RFC 6238 T=59 code = %s, want 287082", got)
	}
	if !verifyTOTPCode(secret, "287082", time.Unix(59, 0)) {
		t.Fatal("valid code rejected")
	}
	// One step of clock skew in either direction is accepted.
	if !verifyTOTPCode(secret, totpCodeAt(secret, time.Unix(29, 0)), time.Unix(59, 0)) {
		t.Fatal("previous-step code rejected within skew window")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef", "28708x"} {
		if verifyTOTPCode(secret, bad, time.Unix(59, 0)) {
			t.Errorf("invalid code %q accepted", bad)
		}
	}
}

func TestMFAToken(t *testing.T) {
	if err := LoadOrGenerateKeys(""); err != nil {
		t.Fatal(err)
	}
	user := User{ID: "user-1", Username: "admin", Role: "admin", TenantID: DefaultTenantID}
	challenge, err := GenerateMFAToken(user)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ValidateMFAToken(challenge.Token)
	if err != nil {
		t.Fatalf("challenge rejected: %v", err)
	}
	if got.ID != user.ID || got.Role != user.Role {
		t.Fatalf("unexpected user from challenge: %+v", got)
	}

	access, err := GenerateAccessToken(user)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateMFAToken(access.Token); err == nil {
		t.Fatal("access token must not be accepted as an MFA challenge")
	}
}
