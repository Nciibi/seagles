# Seagles Roadmap

## Completed — Phases 1 & 2

### Phase 1: Foundation & Security
- [x] Structured logging (`backend/slog/`)
- [x] Circuit breaker for external APIs (`backend/breaker/`)
- [x] Request validation with validator.v10 (all API handlers)
- [x] Graceful shutdown and signal handling
- [x] Correlation ID middleware
- [x] Rate limiting (per-IP sliding window)
- [x] Enhanced security headers (CSP, Permissions-Policy)
- [x] Frontend Error Boundaries
- [x] Frontend loading/skeleton/error states
- [x] FastAPI response models and background tasks

### Phase 2: Performance & Reliability
- [x] WebSocket hub for real-time push
- [x] In-memory cache layer
- [x] Parallel scanning with worker pool (20 concurrent)
- [x] TLS scanner (all versions, weak ciphers, cert expiry)
- [x] Database health monitor with auto-reconnect
- [x] 25+ performance indexes migration
- [x] Expanded port list and adaptive scan flags
- [x] Redis service in docker-compose
- [x] Frontend Service Worker (offline support)
- [x] Virtual scrolling component
- [x] PWA manifest

---

## Completed — Phase 3: Security Hardening

### 3.1 JWT Token Security
- [x] Migrate from HMAC-SHA256 to **RS256** (asymmetric RSA keys)
- [x] Add **refresh token** mechanism (15 min access + 7 day refresh)
- [x] Add **token rotation** and revocation on password change
- [x] Implement **token blacklist** (in-memory with TTL cleanup)
- [x] Add `jti` (token ID) claim for auditability
- [x] `/auth/refresh` endpoint to exchange refresh tokens
- [x] `/auth/logout` endpoint (blacklists current access token)
- [x] `/auth/change-password` endpoint (revokes all refresh tokens)

**Files:** `backend/auth/auth.go`, `backend/auth/tokens.go`, `backend/cache/blacklist.go`, `backend/db/migrations/011_refresh_tokens.sql`, `backend/db/migrations/012_update_users_role.sql`

### 3.2 Role-Based Access Control (RBAC)
- [x] Expand roles beyond admin/viewer: `admin` (3), `operator` (2), `auditor` (1), `viewer` (0)
- [x] Add resource-level permissions (e.g. `devices:scan`, `alerts:ack`, `firmware:*`)
- [x] Add `RequireRole` middleware with role hierarchy
- [x] Add `RequirePermission` middleware with granular permission checks
- [x] Add permission matrix endpoint (`GET /auth/permissions`)
- [x] Add audit log for all permission-denied events

**Files:** `backend/auth/auth.go`, `backend/api/router.go`

### 3.3 Enhanced Rate Limiting
- [x] Refactored into `middleware/ratelimit.go`
- [x] Add per-endpoint rate limit rules (path patterns with wildcards)
- [x] Add per-user rate limits (separate from per-IP)
- [x] Add rate limit headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`)
- [x] Configurable default limit (`RATE_LIMIT_PER_MIN`)
- [x] `AddRule(method, path, limit, window)` for custom rules

**Files:** `backend/middleware/ratelimit.go`, `backend/api/router.go`

### 3.4 Transport & Data Security
- [ ] Enforce TLS 1.3 only in production mode (TBD in deployment config)
- [ ] Add **certificate pinning** for external API calls (NVD, CISA, EPSS)
- [ ] Add **field-level encryption** for sensitive DB columns (TBD)
- [x] Implement **audit logging** for all write operations
- [ ] Add AES-256-GCM encryption for firmware files at rest (TBD)

**Files:** `backend/middleware/audit.go`, `backend/db/migrations/013_audit_log.sql`, `backend/api/router.go`

### 3.5 Input Sanitization & Injection Prevention
- [x] Add **XSS filtering** for all JSON request bodies (automatic via middleware)
- [x] Add request schema validation (via validator.v10 struct tags - done in Phase 1)
- [x] Add file upload validation (magic bytes, file extension verification)
- [ ] Add command injection protection in scanner (nmap args) (TBD)

**Files:** `backend/middleware/sanitize.go`, `backend/api/firmware.go`

### 3.6 Frontend Security
- [x] Add **Content Security Policy** headers (done in Phase 1)
- [x] Add auto-refresh token mechanism (transparent 401 retry)
- [x] Add browser-based logout with API call
- [x] Add refresh token storage for persistent sessions
- [x] Add `logout`, `refreshToken`, `changePassword`, `getPermissions`, `getAuditLog` API calls
- [ ] Add 2FA/TOTP support for admin accounts (TBD)

**Files:** `frontend/src/api/client.ts`, `frontend/src/App.tsx`, `frontend/src/pages/Login.tsx`

---

## Completed — Phase 4: Testing & Documentation

### 4.1 Backend Unit Tests
- [x] `breaker` package: 9 tests (state machine, transitions, concurrency)
- [x] `cache` package: 14 tests (CRUD, TTL, expiry, struct/slice values)
- [x] `cache/blacklist`: 6 tests (add/check/remove/global/concurrent)
- [x] `slog` package: 8 tests (level filtering, key-value, prefix, missing values)
- [x] `risk` package: 14 tests (score calculation, capping, severity, breakdown)
- [x] `auth` package: 17 tests (RSA keys, token sign/verify, expiry, permissions, RBAC)
- [x] `middleware` package: 12 tests (rate limiter, sanitization, CSRF)
- [ ] `scanner` & `api` packages: need DB mock (TBD)

**Total: 80 tests across 6 packages. All passing.**
**Files:** `backend/*_test.go` (7 files)

### 4.2 Backend Integration Tests
- [x] Docker Compose-based integration test suite (`backend/tests/integration_test.go`)
- [x] Full API endpoint testing (health, login, auth/me, refresh, unauthorized/forbidden)
- [x] Test harness with `TestMain` for DB setup + teardown
- [ ] Database migration tests (TBD — needs dedicated test DB)

**Files:** `backend/tests/integration_test.go`

### 4.3 Frontend Tests
- [x] Vitest + Testing Library setup (`vitest.config.ts`, `src/test/setup.ts`)
- [x] ErrorBoundary component tests (render, error state, retry)
- [x] Loading component tests (spinner, skeleton, inline)

**Files:** `frontend/src/components/*.test.tsx`, `frontend/vitest.config.ts`

### 4.4 Performance & Load Testing
- [x] Go benchmark: `breaker.Execute` success — **25.72 ns/op, 0 allocs**
- [x] Go benchmark: `breaker.Execute` mixed — **44.81 ns/op, 13 B/op**
- [x] Go benchmark: `risk.CalculateRiskScore` — **20 ns/op, 0 allocs**
- [x] Go benchmark: `risk.ScoreBreakdown` — **870 ns/op, 712 B/op**
- [x] Go benchmark: `risk.SeverityFromScore` — **0.3 ns/op, 0 allocs**

**Files:** `backend/*_bench_test.go`

### 4.5 API Documentation
- [x] OpenAPI 3.0 spec (`backend/api/swagger.json` — 40+ endpoints)
- [x] Swagger UI endpoint (`GET /api/v1/docs`)
- [x] API documentation (`docs/api.md`)
- [x] WebSocket event types documented
- [x] Error codes, rate limiting headers, RBAC permissions documented
- [ ] Postman/Insomnia collection (TBD)

**Files:** `backend/api/swagger.json`, `backend/api/swagger.go`, `docs/api.md`

### 4.6 Developer Documentation
- [x] Architecture Decision Records (`docs/adr.md` — 9 ADRs)
- [x] Codebase walkthrough (`docs/architecture.md`)
- [x] Troubleshooting guide (`docs/troubleshooting.md`)
- [x] Development setup guide (`docs/setup.md`)

**Files:** `docs/*.md`

### 4.7 CI/CD Pipeline
- [x] GitHub Actions: lint (golangci-lint, eslint)
- [x] GitHub Actions: go vet
- [x] GitHub Actions: test (all packages)
- [x] GitHub Actions: build (backend + frontend)
- [x] GitHub Actions: security scan (Trivy)
- [x] GitHub Actions: Docker image build
- [ ] Automated deployment (TBD)

**Files:** `.github/workflows/ci.yml`

### 4.8 Monitoring & Observability
- [x] Prometheus metrics endpoint (`GET /api/v1/metrics`) — request counts, latency, errors, active, uptime
- [x] Prometheus scrape config (`docker/prometheus/prometheus.yml`)
- [x] Grafana auto-provisioned datasource (`docker/grafana/datasources/`)
- [x] Dashboard provisioning config
- [x] Prometheus + Grafana services in `docker-compose.yml`
- [ ] Distributed tracing (TBD — OpenTelemetry)

**Files:** `backend/middleware/metrics.go`, `docker/prometheus/`, `docker/grafana/`

---

## How to Contribute

1. Pick an item from any phase
2. Create a feature branch: `git checkout -b phase-3.x-short-description`
3. Implement the change
4. Add tests (mandatory for Phase 4 items)
5. Run `make vet && make test` in backend
6. Run `npm run build` in frontend
7. Submit a PR

See `CONTRIBUTING.md` for full contribution guidelines.
