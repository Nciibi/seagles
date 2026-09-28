package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Nciibi/seagles/auth"
	"github.com/Nciibi/seagles/config"
)

func TestResolveJWTKey_PrefersInlineSecret(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:         "INLINE-PEM",
		JWTPrivateKeyFile: "/should/not/be/read",
	}
	got, err := resolveJWTKey(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "INLINE-PEM" {
		t.Errorf("got %q, want INLINE-PEM", got)
	}
}

func TestResolveJWTKey_TrimsWhitespace(t *testing.T) {
	cfg := &config.Config{JWTSecret: "  PEM-WITH-NEWLINES \n"}
	got, err := resolveJWTKey(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "PEM-WITH-NEWLINES" {
		t.Errorf("got %q, want trimmed value", got)
	}
}

func TestResolveJWTKey_ReadsKeyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jwt.pem")
	if err := os.WriteFile(path, []byte("-----BEGIN RSA PRIVATE KEY-----\nabc\n"), 0o600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	cfg := &config.Config{JWTPrivateKeyFile: path}
	got, err := resolveJWTKey(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "BEGIN RSA PRIVATE KEY") {
		t.Errorf("got %q, want the file contents", got)
	}
}

// Regression guard: the original code was
//
//	if keyData, err := os.ReadFile(cfg.JWTPrivateKeyFile); err == nil { ... }
//
// so a configured-but-unreadable key file (missing mount, wrong permissions)
// was swallowed and the process silently generated its own key. That turned a
// deployment error into an intermittent authentication outage across replicas.
func TestResolveJWTKey_UnreadableFileIsAHardError(t *testing.T) {
	cfg := &config.Config{JWTPrivateKeyFile: "/nonexistent/path/jwt.pem"}

	got, err := resolveJWTKey(cfg)
	if err == nil {
		t.Fatalf("expected an error for an unreadable key file, got key %q", got)
	}
	if !strings.Contains(err.Error(), "could not be read") {
		t.Errorf("error should explain the read failure, got: %v", err)
	}
	if !strings.Contains(err.Error(), "/nonexistent/path/jwt.pem") {
		t.Errorf("error should name the offending path, got: %v", err)
	}
}

func TestResolveJWTKey_EmptyFileIsAHardError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	cfg := &config.Config{JWTPrivateKeyFile: path}
	if _, err := resolveJWTKey(cfg); err == nil {
		t.Fatal("expected an error for an empty key file")
	}
}

// No configuration at all must not error: that is the documented single
// instance dev path, where an ephemeral key is generated with a warning.
func TestResolveJWTKey_NothingConfigured(t *testing.T) {
	got, err := resolveJWTKey(&config.Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

// The fatal message must tell an operator exactly what to do, because it is
// the only thing they see when a production pod refuses to start.
func TestRequireSharedJWTKeyMessageIsActionable(t *testing.T) {
	for _, want := range []string{
		"JWT_SECRET",
		"JWT_PRIVATE_KEY_FILE",
		"openssl genrsa 2048",
		"seagles-jwt-secret",
	} {
		if !strings.Contains(REQUIRE_SHARED_JWT_KEY_MSG, want) {
			t.Errorf("startup message does not mention %q, so an operator "+
				"cannot act on it:\n%s", want, REQUIRE_SHARED_JWT_KEY_MSG)
		}
	}
}

func TestUsingEphemeralKey_TracksKeySource(t *testing.T) {
	// A generated key is ephemeral.
	if err := auth.LoadOrGenerateKeys(""); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	if !auth.UsingEphemeralKey() {
		t.Error("UsingEphemeralKey() = false after generating a key, want true")
	}

	// A loaded key is not. Build a real PEM so this exercises the parse path.
	dir := t.TempDir()
	path := filepath.Join(dir, "jwt.pem")
	pem := generateTestRSAPrivateKeyPEM(t)
	if err := os.WriteFile(path, []byte(pem), 0o600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	cfg := &config.Config{JWTPrivateKeyFile: path}
	key, err := resolveJWTKey(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := auth.LoadOrGenerateKeys(key); err != nil {
		t.Fatalf("failed to load key: %v", err)
	}
	if auth.UsingEphemeralKey() {
		t.Error("UsingEphemeralKey() = true after loading a configured key, want false")
	}
}
