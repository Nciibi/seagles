package auth

import (
	"testing"
	"time"
)

func TestLoadOrGenerateKeys_AutoGenerate(t *testing.T) {
	err := LoadOrGenerateKeys("")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if globalKeyPair == nil {
		t.Fatal("expected globalKeyPair to be non-nil")
	}
	if globalKeyPair.PrivateKey == nil {
		t.Fatal("expected private key to be non-nil")
	}
	if globalKeyPair.PublicKey == nil {
		t.Fatal("expected public key to be non-nil")
	}
}

func TestGetPublicKeyPEM(t *testing.T) {
	LoadOrGenerateKeys("")
	pem, err := GetPublicKeyPEM()
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(pem) == 0 {
		t.Fatal("expected non-empty PEM")
	}
}

func TestGenerateAccessToken(t *testing.T) {
	LoadOrGenerateKeys("")
	user := User{ID: "user-1", Username: "testuser", Role: "admin"}

	token, err := GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if token.Token == "" {
		t.Fatal("expected non-empty token string")
	}
	if token.Claims == nil {
		t.Fatal("expected non-nil claims")
	}
	if token.Claims.Sub != "user-1" {
		t.Fatalf("expected Sub='user-1', got '%s'", token.Claims.Sub)
	}
	if token.Claims.Name != "testuser" {
		t.Fatalf("expected Name='testuser', got '%s'", token.Claims.Name)
	}
	if token.Claims.Role != "admin" {
		t.Fatalf("expected Role='admin', got '%s'", token.Claims.Role)
	}
	if token.Claims.TokenType != AccessToken {
		t.Fatalf("expected TokenType=access, got '%s'", token.Claims.TokenType)
	}
	if token.Claims.JTI == "" {
		t.Fatal("expected non-empty jti")
	}
	if token.Claims.IAT == 0 {
		t.Fatal("expected non-zero iat")
	}
	if token.Claims.Exp <= token.Claims.IAT {
		t.Fatal("expected exp > iat")
	}
}

func TestValidateAccessToken(t *testing.T) {
	LoadOrGenerateKeys("")
	user := User{ID: "user-1", Username: "testuser", Role: "viewer"}

	signed, err := GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	validated, err := ValidateAccessToken(signed.Token)
	if err != nil {
		t.Fatalf("ValidateAccessToken failed: %v", err)
	}
	if validated.ID != "user-1" {
		t.Fatalf("expected ID='user-1', got '%s'", validated.ID)
	}
	if validated.Username != "testuser" {
		t.Fatalf("expected Username='testuser', got '%s'", validated.Username)
	}
	if validated.Role != "viewer" {
		t.Fatalf("expected Role='viewer', got '%s'", validated.Role)
	}
}

func TestValidateAccessToken_InvalidSignature(t *testing.T) {
	LoadOrGenerateKeys("")
	user := User{ID: "user-1", Username: "testuser", Role: "admin"}

	signed, _ := GenerateAccessToken(user)
	tampered := signed.Token + "tampered"

	_, err := ValidateAccessToken(tampered)
	if err == nil {
		t.Fatal("expected error for tampered token")
	}
}

func TestValidateAccessToken_Expired(t *testing.T) {
	LoadOrGenerateKeys("")
	user := User{ID: "user-1", Username: "testuser", Role: "admin"}

	claims := &Claims{
		Sub:       user.ID,
		Name:      user.Username,
		Role:      user.Role,
		JTI:       generateTokenID(),
		TokenType: AccessToken,
		IAT:       time.Now().Add(-2 * time.Hour).Unix(),
		Exp:       time.Now().Add(-1 * time.Hour).Unix(),
	}

	tokenStr, err := signRS256(claims)
	if err != nil {
		t.Fatalf("signRS256 failed: %v", err)
	}

	_, err = ValidateAccessToken(tokenStr)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestValidateAccessToken_WrongTokenType(t *testing.T) {
	LoadOrGenerateKeys("")
	user := User{ID: "user-1", Username: "testuser", Role: "admin"}

	claims := &Claims{
		Sub:       user.ID,
		Name:      user.Username,
		Role:      user.Role,
		JTI:       generateTokenID(),
		TokenType: RefreshToken,
		IAT:       time.Now().Unix(),
		Exp:       time.Now().Add(time.Hour).Unix(),
	}

	tokenStr, err := signRS256(claims)
	if err != nil {
		t.Fatalf("signRS256 failed: %v", err)
	}

	_, err = ValidateAccessToken(tokenStr)
	if err == nil {
		t.Fatal("expected error for refresh token used as access token")
	}
}

func TestHashPassword(t *testing.T) {
	hash, err := HashPassword("mysecurepassword")
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}
	if hash == "mysecurepassword" {
		t.Fatal("hash should not equal plaintext")
	}
}

func TestCheckPassword(t *testing.T) {
	hash, _ := HashPassword("correctpw")
	if !CheckPassword("correctpw", hash) {
		t.Fatal("expected CheckPassword to return true for correct password")
	}
	if CheckPassword("wrongpw", hash) {
		t.Fatal("expected CheckPassword to return false for wrong password")
	}
}

func TestRoleHierarchy(t *testing.T) {
	if RoleHierarchy["viewer"] >= RoleHierarchy["auditor"] {
		t.Fatal("expected viewer < auditor")
	}
	if RoleHierarchy["auditor"] >= RoleHierarchy["operator"] {
		t.Fatal("expected auditor < operator")
	}
	if RoleHierarchy["operator"] >= RoleHierarchy["admin"] {
		t.Fatal("expected operator < admin")
	}
}

func TestHasPermission_ExactMatch(t *testing.T) {
	if !HasPermission("admin", "devices:scan") {
		t.Fatal("expected admin to have devices:scan")
	}
	if !HasPermission("viewer", "devices:list") {
		t.Fatal("expected viewer to have devices:list")
	}
	if HasPermission("viewer", "devices:scan") {
		t.Fatal("expected viewer to NOT have devices:scan")
	}
}

func TestHasPermission_Wildcard(t *testing.T) {
	if !HasPermission("admin", "devices:anything") {
		t.Fatal("expected admin to have devices:* wildcard")
	}
	if !HasPermission("admin", "firmware:delete") {
		t.Fatal("expected admin to have firmware:* wildcard")
	}
}

func TestHasPermission_UnknownRole(t *testing.T) {
	if HasPermission("superadmin", "devices:list") {
		t.Fatal("expected unknown role to have no permissions")
	}
}

func TestHasPermission_Viewer(t *testing.T) {
	viewerPerms := []string{
		"devices:list", "devices:view",
		"scans:list", "scans:view",
		"vulnerabilities:list", "vulnerabilities:view",
		"alerts:list", "alerts:view",
		"firmware:list", "firmware:view",
		"stats:view", "kev:view",
	}
	for _, perm := range viewerPerms {
		if !HasPermission("viewer", perm) {
			t.Errorf("expected viewer to have '%s'", perm)
		}
	}

	deniedPerms := []string{"devices:scan", "devices:delete", "alerts:ack", "firmware:upload"}
	for _, perm := range deniedPerms {
		if HasPermission("viewer", perm) {
			t.Errorf("expected viewer to NOT have '%s'", perm)
		}
	}
}

func TestHasPermission_Operator(t *testing.T) {
	if !HasPermission("operator", "devices:scan") {
		t.Fatal("expected operator to have devices:scan")
	}
	if !HasPermission("operator", "vulnerabilities:resolve") {
		t.Fatal("expected operator to have vulnerabilities:resolve")
	}
	if !HasPermission("operator", "alerts:ack") {
		t.Fatal("expected operator to have alerts:ack")
	}
	if HasPermission("operator", "audit:view") {
		t.Fatal("expected operator to NOT have audit:view")
	}
}

func TestHasPermission_Auditor(t *testing.T) {
	if !HasPermission("auditor", "audit:view") {
		t.Fatal("expected auditor to have audit:view")
	}
	if HasPermission("auditor", "devices:scan") {
		t.Fatal("expected auditor to NOT have devices:scan")
	}
}

func TestGenerateTokenID(t *testing.T) {
	id1 := generateTokenID()
	id2 := generateTokenID()
	if len(id1) != 32 {
		t.Fatalf("expected 32 hex chars, got %d", len(id1))
	}
	if id1 == id2 {
		t.Fatal("expected unique token IDs")
	}
}
