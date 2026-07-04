# IronMesh Roadmap

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

## Upcoming — Phase 4: Testing & Documentation

### 4.1 Backend Unit Tests
- [ ] 100% coverage for `breaker` package
- [ ] 100% coverage for `cache` package
- [ ] 100% coverage for `risk/scorer.go`
- [ ] 90%+ coverage for `scanner` package (mock nmap)
- [ ] 90%+ coverage for `auth` package
- [ ] Property-based tests for risk score calculation

**Files:** `backend/*_test.go` (new files for each package)

### 4.2 Backend Integration Tests
- [ ] Docker Compose-based integration test suite
- [ ] Full API endpoint testing with test database
- [ ] Database migration tests (up/down)
- [ ] Scanner integration test with mock nmap
- [ ] Webhook delivery integration test

**Files:** `backend/tests/` (new directory)

### 4.3 Frontend Tests
- [ ] Component tests for all pages (Vitest + Testing Library)
- [ ] Integration tests for API client
- [ ] Accessibility testing (axe-core)
- [ ] E2E tests with Playwright/Cypress
- [ ] Visual regression tests

**Files:** `frontend/src/**/*.test.tsx`, `frontend/e2e/`

### 4.4 Performance & Load Testing
- [ ] Go benchmark tests for critical paths
- [ ] k6/Gatling load test scenarios
- [ ] Database query profiling and optimization
- [ ] Frontend Lighthouse CI scores (target 90+)
- [ ] Memory profiling for firmware analyzer

**Files:** `backend/*_bench_test.go`, `tests/load/`

### 4.5 API Documentation
- [ ] Generate OpenAPI 3.0 spec from Go code
- [ ] Add Swagger UI endpoint
- [ ] Document all WebSocket event types
- [ ] Create API changelog
- [ ] Add Postman/Insomnia collection

**Files:** `docs/api.md`, `docs/websocket.md`, `api/swagger.json`

### 4.6 Developer Documentation
- [ ] Architecture Decision Records (ADRs)
- [ ] Codebase walkthrough for each module
- [ ] Troubleshooting guide (common issues)
- [ ] Development setup guide (detailed)
- [ ] Deployment checklist
- [ ] Security audit checklist

**Files:** `docs/architecture.md`, `docs/troubleshooting.md`, `docs/deployment.md`

### 4.7 CI/CD Pipeline
- [ ] GitHub Actions: lint (golangci-lint, eslint)
- [ ] GitHub Actions: test matrix (Go 1.24, 1.25)
- [ ] GitHub Actions: security scan (Trivy, SonarQube)
- [ ] GitHub Actions: build and push Docker images
- [ ] GitHub Actions: E2E tests on PR
- [ ] Automated dependency updates (Renovate bot)
- [ ] Blue-green deployment script
- [ ] Automated rollback on test failure

**Files:** `.github/workflows/ci.yml`, `.github/workflows/deploy.yml`, `.github/renovate.json`

### 4.8 Monitoring & Observability
- [ ] Prometheus metrics endpoint (`/metrics`)
- [ ] Structured log aggregation (Loki/Datadog)
- [ ] Health check dashboard
- [ ] Slack/PagerDuty alert integration for critical failures
- [ ] Grafana dashboard templates
- [ ] Distributed tracing (OpenTelemetry)

**Files:** `backend/middleware/metrics.go`, `docker/grafana/`, `docker/prometheus/`

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
