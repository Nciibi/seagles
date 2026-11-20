// Package meta holds build-wide constants shared across Seagles packages.
// Keeping them here gives the release version and the default tenant a single
// source of truth instead of duplicated literals that can silently drift.
package meta

const (
	// Version is the Seagles release identifier, reported by the API health
	// endpoint and the startup banner. Keep it in sync with the frontend's
	// package.json version.
	Version = "2.1.0"

	// DefaultTenantID is the tenant every pre-multitenancy row was backfilled
	// to by migration 015. Single-tenant deployments continue to use it.
	DefaultTenantID = "00000000-0000-0000-0000-000000000001"
)
