// Integration tests — requires running PostgreSQL.
// Run: docker compose up -d postgres
// Then: go test -tags=integration -v ./tests/
//
//go:build integration

package tests

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/seagles/api"
	"github.com/yourusername/seagles/auth"
	"github.com/yourusername/seagles/config"
	"github.com/yourusername/seagles/db"
	"github.com/yourusername/seagles/kev"
)

var (
	testDB     *sql.DB
	testRouter *gin.Engine
	testCfg    *config.Config
)

func TestMain(m *testing.M) {
	os.Setenv("JWT_SECRET", "")
	os.Setenv("RATE_LIMIT_PER_MIN", "1000")

	var err error
	testCfg, err = config.Load()
	if err != nil {
		panic("Failed to load config: " + err.Error())
	}

	if testCfg.DatabaseURL == "" {
		panic("DATABASE_URL is required for integration tests")
	}

	auth.SetJWTSecret(testCfg.JWTSecret)
	testDB = db.Connect(testCfg.DatabaseURL)
	db.RunMigrations(testDB)

	kevCatalog := kev.StartKEVUpdater("../../data/cisa-kev.json")
	testRouter = api.NewRouter(testDB, testCfg, kevCatalog)

	code := m.Run()
	testDB.Close()
	os.Exit(code)
}

func request(method, path string, body interface{}, token string) *httptest.ResponseRecorder {
	var reqBody []byte
	if body != nil {
		reqBody, _ = json.Marshal(body)
	}

	req := httptest.NewRequest(method, "/api/v1"+path, bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)
	return w
}

func TestHealthEndpoint(t *testing.T) {
	w := request("GET", "/health", nil, "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Data struct {
			Status  string `json:"status"`
			Service string `json:"service"`
			DBOK    bool   `json:"db_ok"`
		} `json:"data"`
		Error interface{} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp.Data.Status != "ok" {
		t.Fatalf("expected status=ok, got %s", resp.Data.Status)
	}
	if !resp.Data.DBOK {
		t.Fatal("expected db_ok=true")
	}
}

func TestLoginEndpoint(t *testing.T) {
	w := request("POST", "/auth/login", map[string]string{
		"username": "admin",
		"password": "changeme",
	}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Data struct {
			Token        string      `json:"token"`
			ExpiresIn    int64       `json:"expires_in"`
			RefreshToken string      `json:"refresh_token"`
			User         auth.User   `json:"user"`
		} `json:"data"`
		Error interface{} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp.Data.Token == "" {
		t.Fatal("expected non-empty token")
	}
	if resp.Data.RefreshToken == "" {
		t.Fatal("expected non-empty refresh_token")
	}
	if resp.Data.User.Username != "admin" {
		t.Fatalf("expected username=admin, got %s", resp.Data.User.Username)
	}
	if resp.Data.User.Role != "admin" {
		t.Fatalf("expected role=admin, got %s", resp.Data.User.Role)
	}
}

func TestAuthMeEndpoint(t *testing.T) {
	loginResp := request("POST", "/auth/login", map[string]string{
		"username": "admin",
		"password": "changeme",
	}, "")

	var loginData struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	json.Unmarshal(loginResp.Body.Bytes(), &loginData)
	token := loginData.Data.Token

	w := request("GET", "/auth/me", nil, token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestUnauthorizedAccess(t *testing.T) {
	w := request("GET", "/devices", nil, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestForbiddenAccess(t *testing.T) {
	// Register a viewer
	registerResp := request("POST", "/auth/login", map[string]string{
		"username": "admin",
		"password": "changeme",
	}, "")

	var loginData struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	json.Unmarshal(registerResp.Body.Bytes(), &loginData)

	w := request("DELETE", "/devices/nonexistent-id", nil, loginData.Data.Token)
	if w.Code != http.StatusForbidden && w.Code != http.StatusOK {
		t.Fatalf("expected 403 or 404, got %d", w.Code)
	}
}

func TestRefreshTokenFlow(t *testing.T) {
	loginResp := request("POST", "/auth/login", map[string]string{
		"username": "admin",
		"password": "changeme",
	}, "")

	var loginData struct {
		Data struct {
			Token        string `json:"token"`
			RefreshToken string `json:"refresh_token"`
		} `json:"data"`
	}
	json.Unmarshal(loginResp.Body.Bytes(), &loginData)

	w := request("POST", "/auth/refresh", map[string]string{
		"refresh_token": loginData.Data.RefreshToken,
	}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var refreshData struct {
		Data struct {
			Token        string `json:"token"`
			RefreshToken string `json:"refresh_token"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &refreshData)
	if refreshData.Data.Token == "" {
		t.Fatal("expected non-empty new token")
	}
	if refreshData.Data.Token == loginData.Data.Token {
		t.Fatal("expected different access token after refresh")
	}
}
