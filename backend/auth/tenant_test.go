package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestTenantFromContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if got := TenantFromContext(c); got != DefaultTenantID {
		t.Fatalf("empty context tenant = %q, want default", got)
	}

	c.Set(TenantContextKey, "11111111-1111-1111-1111-111111111111")
	if got := TenantFromContext(c); got != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("context tenant = %q", got)
	}

	if got := TenantFromContext(nil); got != DefaultTenantID {
		t.Fatalf("nil context tenant = %q, want default", got)
	}
}

func TestLoginTenantUsesValidHeaderOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const tenant = "33333333-3333-3333-3333-333333333333"

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	if got := LoginTenant(c); got != DefaultTenantID {
		t.Fatalf("no header tenant = %q, want default", got)
	}

	c.Request.Header.Set("X-Tenant-ID", tenant)
	if got := LoginTenant(c); got != tenant {
		t.Fatalf("valid header tenant = %q, want %q", got, tenant)
	}

	c.Request.Header.Set("X-Tenant-ID", "not-a-uuid")
	if got := LoginTenant(c); got != DefaultTenantID {
		t.Fatalf("invalid header tenant = %q, want default", got)
	}
}

func TestAccessTokenKeepsExplicitTenant(t *testing.T) {
	withTestKeys(t)
	const tenant = "22222222-2222-2222-2222-222222222222"
	token, err := GenerateAccessToken(User{ID: "u1", Username: "admin", Role: "admin", TenantID: tenant})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if token.Claims.TenantID != tenant {
		t.Fatalf("claim tenant = %q, want %q", token.Claims.TenantID, tenant)
	}
	user, err := ValidateAccessToken(token.Token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if user.TenantID != tenant {
		t.Fatalf("user tenant = %q, want %q", user.TenantID, tenant)
	}
}
