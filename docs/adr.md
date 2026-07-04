# Architecture Decision Records

## ADR-001: Custom JWT over Standard Library

**Status:** Accepted  
**Date:** 2026-07-04  

**Context:** Need token-based auth with refresh token rotation and revocation.

**Decision:** Implement RS256 JWT signing using Go standard library (`crypto/rsa`, `crypto/sha256`) instead of `golang-jwt/jwt`.

**Consequences:**
- Zero external dependency for JWT
- Full control over claims structure and validation
- Slightly more code to maintain, but the JWT format is well-understood
- Public key endpoint for third-party verification

**Alternatives considered:**
- `golang-jwt/jwt` — popular but adds dependency; not needed for standard RS256
- HMAC-SHA256 — simpler but symmetric; can't safely distribute verification key

---

## ADR-002: In-Memory Cache over Redis

**Status:** Accepted  
**Date:** 2026-07-04  

**Context:** Need caching for stats, device data, and firmware analysis results.

**Decision:** Implement generic `Cache[T]` with TTL support using in-memory maps.

**Consequences:**
- Zero external dependencies for basic operation
- Cache lost on restart (acceptable for TTL-based cache)
- Redis URL config is plumbed for future swap
- Token blacklist uses same in-memory approach (24h max TTL)

**Alternatives considered:**
- Redis — production-ready but adds deployment complexity
- Memcached — similar complexity to Redis with fewer features

---

## ADR-003: Circuit Breaker over Retry

**Status:** Accepted  
**Date:** 2026-07-04  

**Context:** External API calls to CISA KEV, FIRST EPSS, and NVD may fail intermittently.

**Decision:** Implement circuit breaker with Closed/Half-Open/Open state machine.

**Consequences:**
- Prevents cascading failures during API outages
- Configurable thresholds per external service
- Automatic recovery via half-open probing
- Graceful degradation (cache stale data or return partial results)

**Alternatives considered:**
- Retry with exponential backoff — doesn't prevent cascading failures
- Timeout only — no protection against sustained outages

---

## ADR-004: Structured Logging over Logrus/Zap

**Status:** Accepted  
**Date:** 2026-07-04  

**Context:** Need structured logging with levels, key-value pairs, and request correlation.

**Decision:** Implement minimal structured logger in-house.

**Consequences:**
- ~100 lines of code vs. importing heavy logging frameworks
- Same key=value output convention as standard tools
- Correlation IDs added at middleware layer, not in logger
- Easy to swap for zerolog/logrus if performance becomes an issue

**Alternatives considered:**
- logrus — popular but heavy (50+ exports)
- zap — fastest but complex configuration

---

## ADR-005: RS256 JWT over HMAC

**Status:** Accepted  
**Date:** 2026-07-04  

**Context:** Initial implementation used HMAC-SHA256 with shared secret. Need to support token verification by external services (microservices, third-party integrations).

**Decision:** Migrate from HMAC-SHA256 to RS256 (RSA PKCS#1 v1.5 with SHA-256).

**Consequences:**
- Public key can be shared for verification without exposing signing key
- 2048-bit RSA key auto-generated if none configured
- PEM key file path supported for production deployments
- Slightly larger tokens (~350 bytes vs ~180 bytes HMAC)

---

## ADR-006: RBAC with Hierarchical Roles

**Status:** Accepted  
**Date:** 2026-07-04  

**Context:** Need granular access control across teams (security ops, auditors, admins).

**Decision:** Implement role hierarchy with permission sets.

**Consequences:**
- 4 roles: viewer (0), auditor (1), operator (2), admin (3)
- Hierarchical `RequireRole()` middleware for level-based checks
- Granular `RequirePermission()` for resource-level access
- Permissions follow `<resource>:<action>` convention
- Admin gets `<resource>:*` wildcards

**Alternatives considered:**
- Casbin — powerful but adds significant complexity
- Flat permissions — too many per-route annotations

---

## ADR-007: Audit Logging as Middleware

**Status:** Accepted  
**Date:** 2026-07-04  

**Context:** Need to track all write operations for compliance and incident response.

**Decision:** Implement audit logging as Gin middleware that auto-captures write operations.

**Consequences:**
- Zero code changes to existing handlers
- Captures: user, action, resource, IP, user-agent, status, latency
- Stores in `audit_log` table with 90-day retention
- Auditor role can view audit log via API
- Skip paths configured for auth endpoints to avoid noise

---

## ADR-008: XSS Filtering via Middleware

**Status:** Accepted  
**Date:** 2026-07-04  

**Context:** User-supplied text fields (device names, notes, alert comments) may contain XSS payloads.

**Decision:** Implement XSS filtering as request middleware for all JSON bodies.

**Consequences:**
- Strips dangerous HTML/script content from all incoming JSON
- Case-insensitive detection of `<script>`, `<iframe>`, `onerror=`, `javascript:`
- Zero handler changes needed
- File uploads validated via magic bytes + extension whitelist

---

## ADR-009: File Upload Validation by Magic Bytes

**Status:** Accepted  
**Date:** 2026-07-04  

**Context:** Firmware uploads could contain arbitrary data; need to validate without trusting file extension.

**Decision:** Read first 512 bytes and match against known magic byte signatures.

**Consequences:**
- Supports: gzip, bzip2, xz, zip, rar, 7z, ELF
- File extension whitelist as secondary check
- Rejects empty files and oversized payloads (>256MB)
- Validation before write prevents wasted I/O

---

## ADR-010: WebSocket with Origin Whitelist

**Status:** Accepted  
**Date:** 2026-07-04  

**Context:** WebSocket connections must be secured against cross-origin WebSocket hijacking (CSWSH) and unauthorized access.

**Decision:** Implement WebSocket with origin whitelist verification and JWT authentication middleware.

**Consequences:**
- `CheckOrigin` verifies against `ALLOWED_ORIGINS` env var (comma-separated)
- WebSocket route placed inside authenticated Gin group (JWT required)
- `Broadcast()` uses `Lock()` instead of `RLock()` to prevent data race
- Unauthenticated connections are rejected before upgrade

**Alternatives considered:**
- Permissive `CheckOrigin: true` — original bug, removed
- Token in query string — less secure, logged by proxies

---

## ADR-011: React Router for Client-Side Routing

**Status:** Accepted  
**Date:** 2026-07-04  

**Context:** Need client-side routing for SPA with protected routes, login redirects, and deep-linking to device details.

**Decision:** Use React Router v6 with `BrowserRouter`.

**Consequences:**
- Declarative route definitions with `<Route>` nesting
- `<Navigate>` for auth redirects
- URL params for device IDs (`/devices/:id`)
- Future `v7_startTransition` flag ready for React 19
- `createRoutesFromElements` pattern for route composition

**Alternatives considered:**
- TanStack Router — newer but less ecosystem adoption
- Next.js — would require full framework migration, not SPA

---

## ADR-012: Recharts for Data Visualization

**Status:** Accepted  
**Date:** 2026-07-04  

**Context:** Need charts for risk score distribution, vulnerability trends, and scan history.

**Decision:** Use Recharts (React + D3 wrapper) for all data visualization.

**Consequences:**
- Declarative chart components (`<BarChart>`, `<PieChart>`, `<LineChart>`)
- Responsive containers with `<ResponsiveContainer>`
- Bundle weight ~150KB gzipped (acceptable for analytics page)
- Easy customization via standard React props

**Alternatives considered:**
- Chart.js + react-chartjs-2 — similar bundle, imperative API
- D3 directly — more flexible but much higher complexity
- Nivo — beautiful but heavier bundle

---

## ADR-013: TailwindCSS over CSS-in-JS

**Status:** Accepted  
**Date:** 2026-07-04  

**Context:** Need consistent styling with minimal runtime overhead and fast iteration.

**Decision:** Use TailwindCSS with utility classes for all styling.

**Consequences:**
- Zero runtime CSS-in-JS overhead
- Consistent design tokens (colors, spacing, typography) via `tailwind.config.js`
- Dark mode via `class` strategy
- PostCSS purge removes unused styles in production
- Some inline styles remain for dynamic values (risk colors)

**Alternatives considered:**
- CSS Modules — scoped but verbose for complex components
- Styled Components — runtime overhead, harder to debug
- Plain CSS — global namespace collisions

---

## ADR-014: nginx for Frontend Serving

**Status:** Accepted  
**Date:** 2026-07-04  

**Context:** Need to serve built React SPA with compression, caching, and API proxying.

**Decision:** Use nginx:alpine as production frontend server.

**Consequences:**
- Gzip/brotli compression of static assets
- `Cache-Control: immutable` for hashed assets (1 year)
- `Cache-Control: no-cache` for index.html
- API proxy to backend (avoiding CORS in production)
- SPA fallback (`try_files $uri /index.html`)
- Runs as non-root user (security best practice)

**Alternatives considered:**
- Caddy — simpler config but less familiar to DevOps
- Node.js (serve) — more resource-intensive, no native compression
- Cloudflare Pages — external dependency

---

## ADR-015: Service Worker for PWA + Offline Cache

**Status:** Accepted  
**Date:** 2026-07-04  

**Context:** Need offline capability and installable PWA for field use (security engineers on client sites).

**Decision:** Implement service worker with cache-first strategy for static assets and network-first for API calls.

**Consequences:**
- App shell cached on first visit (instant load on return)
- Dashboard data cached for offline viewing
- Push notification support for critical alerts
- Manifest.json for "Add to Home Screen"
- Versioned cache busting on deploy

**Alternatives considered:**
- Workbox — powerful but adds dependency
- No SW — no offline capability, poor mobile experience

---

## ADR-016: Gin Web Framework over net/http

**Status:** Accepted  
**Date:** 2026-07-04  

**Context:** Need HTTP framework with routing, middleware chaining, request binding, and response rendering.

**Decision:** Use Gin (gin-gonic/gin) as the HTTP framework.

**Consequences:**
- Declarative router groups with path parameters (`/devices/:id`)
- Built-in request validation via `ShouldBindJSON` + struct tags
- Middleware chain with `Use()` for cross-cutting concerns
- High performance (minimal reflection overhead)
- Recovery middleware for panic handling

**Alternatives considered:**
- `net/http` — zero dependencies but manual routing and no built-in middleware
- Echo — similar performance but smaller ecosystem
- Chi — lightweight but fewer built-in features

---

## ADR-017: Worker Pool for Scan Concurrency

**Status:** Accepted  
**Date:** 2026-07-04  

**Context:** Network scanning is resource-intensive. Unbounded concurrency could saturate the host network and CPU.

**Decision:** Implement a bounded worker pool (20 goroutines) for scan operations.

**Consequences:**
- Controlled resource usage during network scans
- Worker pool configured via `SCAN_MAX_CONCURRENT` env var
- Jobs submitted via buffered channel with backpressure
- Graceful shutdown drains in-progress scans

**Alternatives considered:**
- Unbounded goroutines — simpler but risk of resource exhaustion
- Semaphore pattern — equivalent but less encapsulated
- External job queue (RabbitMQ) — overkill for current scale

---

## ADR-018: bcrypt for Password Hashing

**Status:** Accepted  
**Date:** 2026-07-04  

**Context:** Need password storage that resists brute-force and rainbow table attacks.

**Decision:** Use bcrypt with cost factor 12.

**Consequences:**
- ~250ms per hash verification (acceptable for auth login)
- Built-in salt eliminates rainbow table risk
- Cost factor tunable for future hardware improvements
- Standard library `golang.org/x/crypto/bcrypt`

**Alternatives considered:**
- SHA-256 with salt — fast but lacks work factor
- Argon2 — more modern but requires CGO on some platforms
- scrypt — memory-hard but less widely supported in Go

---

## ADR-019: Axios with Interceptor for Token Refresh

**Status:** Accepted  
**Date:** 2026-07-04  

**Context:** Frontend needs automatic token refresh when access tokens expire, with retry of failed requests.

**Decision:** Use Axios HTTP client with response interceptor for token refresh.

**Consequences:**
- Interceptor catches 401 responses, refreshes token, retries original request
- Request queue prevents concurrent refresh calls
- Failed refreshes redirect to login page
- FormData upload support for firmware files

**Alternatives considered:**
- Fetch API — no built-in interceptor pattern
- ky — newer but smaller ecosystem
- Plain XMLHttpRequest — verbose and error-prone

---

## ADR-020: Prometheus for Metrics Collection

**Status:** Accepted  
**Date:** 2026-07-04  

**Context:** Need application metrics (request count, latency, error rate) for monitoring and alerting.

**Decision:** Expose Prometheus metrics at `GET /metrics` and provide Grafana dashboards.

**Consequences:**
- Industry-standard pull-based metrics collection
- 4 pre-built Grafana dashboards (security overview, device health, scan performance, audit trail)
- Metrics grouped by endpoint, method, and status code
- Uses `prometheus/client_golang` with Gin middleware
- Zero external monitoring dependencies (Prometheus + Grafana in Docker Compose)

**Alternatives considered:**
- OpenTelemetry — more comprehensive but significantly more complex
- Datadog/New Relic agents — vendor lock-in and cost
- StatsD — push-based, requires aggregator

