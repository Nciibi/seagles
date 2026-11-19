package auth

import (
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
