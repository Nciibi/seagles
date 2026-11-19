package auth

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const TenantContextKey = "tenant_id"

// TenantFromContext returns the tenant of the authenticated principal. It is
// populated by AuthMiddleware from the verified JWT and falls back to the
// default tenant for callers outside an authenticated request (background
// workers and single-tenant deployments).
//
// Handlers that issue tenant-scoped queries must use this value; relying on
// the transitional tenant_id DEFAULT in migration 015 would silently write
// into the default tenant instead of the caller's.
func TenantFromContext(c *gin.Context) string {
	if c == nil {
		return DefaultTenantID
	}
	if value, exists := c.Get(TenantContextKey); exists {
		if tenantID, ok := value.(string); ok && tenantID != "" {
			return tenantID
		}
	}
	return DefaultTenantID
}

// LoginTenant resolves the tenant dimension supplied at login. Usernames are
// unique per tenant, so a bare username cannot identify an account on a
// multi-tenant deployment. X-Tenant-ID is only a routing hint: the password is
// still verified, so a forged header cannot authenticate as another tenant's
// user. Invalid hints fall back to the default tenant instead of being trusted.
func LoginTenant(c *gin.Context) string {
	if c == nil {
		return DefaultTenantID
	}
	hint := strings.TrimSpace(c.GetHeader("X-Tenant-ID"))
	if hint == "" {
		return DefaultTenantID
	}
	if _, err := uuid.Parse(hint); err != nil {
		return DefaultTenantID
	}
	return hint
}
