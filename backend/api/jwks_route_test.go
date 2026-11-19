package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/Nciibi/seagles/auth"
	"github.com/Nciibi/seagles/config"
)

func TestJWKSEndpointIsPublicAndServesTheSigningKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	if err := auth.LoadOrGenerateKeys(""); err != nil {
		t.Fatalf("load keys: %v", err)
	}

	router := NewRouter(nil, &config.Config{}, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/jwks.json", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Keys []struct {
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body.Keys) != 1 || body.Keys[0].Kty != "RSA" || body.Keys[0].Alg != "RS256" {
		t.Fatalf("unexpected JWKS body: %s", rec.Body.String())
	}
	if body.Keys[0].N == "" || body.Keys[0].E == "" {
		t.Fatal("JWK is missing modulus or exponent")
	}
	if got := rec.Header().Get("Cache-Control"); got == "" {
		t.Fatal("JWKS response is missing Cache-Control")
	}
}

func TestPublicKeyPEMEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	if err := auth.LoadOrGenerateKeys(""); err != nil {
		t.Fatalf("load keys: %v", err)
	}

	router := NewRouter(nil, &config.Config{}, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/public-key.pem", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "BEGIN PUBLIC KEY") {
		t.Fatalf("response is not a PEM public key: %s", rec.Body.String())
	}
}
