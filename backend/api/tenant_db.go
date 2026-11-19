package api

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Nciibi/seagles/auth"
	"github.com/Nciibi/seagles/slog"
)

// DBTX is the subset of database operations handlers use. Both *sql.DB and
// *sql.Tx implement it, so a request can transparently use a transaction whose
// app.tenant_id GUC is set by TenantDBMiddleware.
type DBTX interface {
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
	Exec(query string, args ...interface{}) (sql.Result, error)
}

const tenantDBContextKey = "tenant_db"

// TenantDBMiddleware binds a transaction to each authenticated request and
// sets app.tenant_id locally on it. Migration 017's RLS policies use that
// value to filter every read and check every write. set_config(..., true) is
// transaction-local, so the GUC disappears when the transaction ends and a
// pooled connection can never inherit another tenant's context.
func TenantDBMiddleware(pool *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		if pool == nil {
			c.Next()
			return
		}
		tenantID := auth.TenantFromContext(c)
		ctx := c.Request.Context()

		tx, err := pool.BeginTx(ctx, nil)
		if err != nil {
			failInternal(c, http.StatusServiceUnavailable, "Database unavailable", err)
			c.Abort()
			return
		}

		if _, err := tx.ExecContext(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID); err != nil {
			tx.Rollback()
			failInternal(c, http.StatusServiceUnavailable, "Database unavailable", err)
			c.Abort()
			return
		}

		c.Set(tenantDBContextKey, tx)
		c.Next()

		if err := tx.Commit(); err != nil {
			slog.Error("Failed to commit request transaction", "error", err.Error())
		}
	}
}

// tenantDB returns the request-scoped transaction when middleware installed
// one, otherwise the pool. The fallback keeps health probes and tests (which
// build a router without this middleware) working.
func tenantDB(c *gin.Context, pool *sql.DB) DBTX {
	if value, exists := c.Get(tenantDBContextKey); exists {
		if tx, ok := value.(*sql.Tx); ok {
			return tx
		}
	}
	return pool
}
