package middleware

import (
	"testing"
)

func TestGenerateCSRFToken(t *testing.T) {
	t1 := generateCSRFToken()
	t2 := generateCSRFToken()
	if len(t1) == 0 {
		t.Fatal("expected non-empty token")
	}
	if t1 == t2 {
		t.Fatal("expected unique tokens")
	}
}

func TestHashToken(t *testing.T) {
	h1 := hashToken("test-token")
	h2 := hashToken("test-token")
	if h1 != h2 {
		t.Fatal("expected same hash for same input")
	}
	if len(h1) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(h1))
	}
}

func TestSetAndValidateCSRFToken(t *testing.T) {
	token := generateCSRFToken()
	hash := hashToken(token)

	globalCSRF.mu.Lock()
	globalCSRF.tokens[hash] = time.Now().Add(globalCSRF.maxAge)
	globalCSRF.mu.Unlock()

	if !ValidateCSRFToken(token) {
		t.Fatal("expected token to be valid")
	}

	if ValidateCSRFToken(token) {
		t.Fatal("expected token to be invalid after single use")
	}
}

func TestValidateCSRFToken_Invalid(t *testing.T) {
	if ValidateCSRFToken("nonexistent-token") {
		t.Fatal("expected nonexistent token to be invalid")
	}
}

func TestValidateCSRFToken_Expired(t *testing.T) {
	token := generateCSRFToken()
	hash := hashToken(token)

	globalCSRF.mu.Lock()
	globalCSRF.tokens[hash] = -1
	globalCSRF.mu.Unlock()

	if ValidateCSRFToken(token) {
		t.Fatal("expected expired token to be invalid")
	}
}
