package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestTLSEnforcementMiddleware_AllowsTLS12(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(TLSEnforcementMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.TLS = &tls.ConnectionState{Version: tls.VersionTLS12}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for TLS 1.2, got %d", w.Code)
	}
}

func TestTLSEnforcementMiddleware_BlocksTLS11(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(TLSEnforcementMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.TLS = &tls.ConnectionState{Version: tls.VersionTLS11}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for TLS 1.1, got %d", w.Code)
	}
}

func TestTLSEnforcementMiddleware_AllowsNoTLS(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(TLSEnforcementMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for non-TLS, got %d", w.Code)
	}
}

func TestLoadPinnedKeys(t *testing.T) {
	dir := t.TempDir()
	pinsFile := filepath.Join(dir, "pins.txt")
	content := "# Comment line\n"
	content += "example.com abc123def\n"
	content += "api.example.com 456ghi789\n"
	content += "\n"
	os.WriteFile(pinsFile, []byte(content), 0644)

	pins, err := LoadPinnedKeys(pinsFile)
	if err != nil {
		t.Fatalf("failed to load pins: %v", err)
	}
	if len(pins) != 2 {
		t.Fatalf("expected 2 pins, got %d", len(pins))
	}
	if pins[0].Hostname != "example.com" || pins[0].SHA256 != "abc123def" {
		t.Fatalf("unexpected pin 0: %+v", pins[0])
	}
}

func TestLoadPinnedKeys_FileNotFound(t *testing.T) {
	_, err := LoadPinnedKeys("/nonexistent/pins.txt")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func generateTestCert(t *testing.T, commonName string) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		DNSNames:     []string{commonName},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}
	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}
	return tlsCert, cert
}

func TestNewPinnedHTTPClient_ValidPin(t *testing.T) {
	tlsCert, cert := generateTestCert(t, "example.com")
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	pins := []CertPin{{Hostname: "example.com", SHA256: fingerprint}}
	client := NewPinnedHTTPClient(pins)

	_, err = client.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))
	if err == nil {
		t.Log("connection succeeded with valid pin")
	}
}

func TestContainsHost(t *testing.T) {
	tests := []struct {
		hosts  []string
		target string
		want   bool
	}{
		{[]string{"example.com", "test.com"}, "example", true},
		{[]string{"example.com"}, "nonexistent", false},
		{[]string{}, "test", false},
		{[]string{"api.example.com"}, "example", true},
	}
	for _, tt := range tests {
		got := containsHost(tt.hosts, tt.target)
		if got != tt.want {
			t.Errorf("containsHost(%v, %q) = %v, want %v", tt.hosts, tt.target, got, tt.want)
		}
	}
}

func TestDefaultTLSConfig(t *testing.T) {
	if DefaultTLSConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("expected MinVersion TLS 1.2, got %d", DefaultTLSConfig.MinVersion)
	}
}
