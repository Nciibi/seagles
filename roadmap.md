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

## Upcoming — Phase 3: Security Hardening

### 3.1 JWT Token Security
- [ ] Migrate from HMAC-SHA256 to **RS256** (asymmetric RSA keys)
- [ ] Add **refresh token** mechanism (short-lived access + long-lived refresh)
- [ ] Add **token rotation** and revocation on password change
- [ ] Implement **token blacklist** (Redis-backed for O(1) checks)
- [ ] Add `jti` (token ID) claim for auditability

**Files:** `backend/auth/auth.go`, `backend/auth/tokens.go`, `backend/cache/blacklist.go`

### 3.2 Role-Based Access Control (RBAC)
- [ ] Expand roles beyond admin/viewer: `admin`, `operator`, `viewer`, `auditor`
- [ ] Add resource-level permissions (e.g. `devices:scan`, `alerts:ack`)
- [ ] Add permission check middleware
- [ ] Add permission matrix endpoint for UI
- [ ] Add audit log for all permission-denied events

**Files:** `backend/auth/rbac.go`, `backend/auth/middleware.go`, `backend/db/migrations/011_rbac.sql`

### 3.3 Enhanced Rate Limiting
- [ ] Add per-endpoint rate limits (e.g. `/scan/network` stricter than `/devices`)
- [ ] Add per-user rate limits (separate from per-IP)
- [ ] Add rate limit headers (`X-RateLimit-Remaining`, `X-RateLimit-Reset`)
- [ ] Implement token bucket algorithm for burst handling
- [ ] Store rate limit state in Redis for distributed deployments

**Files:** `backend/api/ratelimit.go` (upgrade from inline middleware)

### 3.4 Transport & Data Security
- [ ] Enforce TLS 1.3 only in production mode
- [ ] Add **certificate pinning** for external API calls (NVD, CISA, EPSS)
- [ ] Add **field-level encryption** for sensitive DB columns (passwords, secrets)
- [ ] Implement **audit logging** for all write operations (CRUD on devices, vulns, users)
- [ ] Add AES-256-GCM encryption for firmware files at rest (S3/server)

**Files:** `backend/crypto/encrypt.go`, `backend/middleware/audit.go`, `backend/db/migrations/012_audit_log.sql`

### 3.5 Input Sanitization & Injection Prevention
- [ ] Add SQL injection detection middleware (queries already use parameterized SQL)
- [ ] Add XSS filtering for all user-supplied text fields
- [ ] Add request schema validation middleware
- [ ] Add file upload validation (magic bytes, MIME type verification)
- [ ] Add command injection protection in scanner (nmap args)

**Files:** `backend/middleware/sanitize.go`, `backend/api/upload.go` (upgrade)

### 3.6 Frontend Security
- [ ] Add **Content Security Policy** reporting endpoint
- [ ] Add Subresource Integrity (SRI) hashes for CDN assets
- [ ] Implement secure session storage (HttpOnly cookies vs localStorage)
- [ ] Add CSRF token protection for state-changing requests
- [ ] Add 2FA/TOTP support for admin accounts

**Files:** `frontend/src/auth/SecureStorage.ts`, `frontend/src/auth/TwoFactor.ts`

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
