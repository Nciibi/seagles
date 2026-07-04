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
