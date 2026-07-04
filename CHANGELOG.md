# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-07-04

### Added
- Full test suite: 35 frontend tests (6 suites) + 60+ backend tests (9 suites)
- API handler tests with `sqlmock` + `httptest` for devices, scans, vulns, alerts, firmware, safelists, webhooks, scan-scopes, scan-profiles, stats, risk-breakdown
- Middleware audit + TLS enforcement tests
- Scanner protocol detection tests with local TCP servers (Telnet, ADB, MQTT, Modbus, RTSP)
- Config validation tests (defaults, env overrides, error paths)
- Risk scoring DB tests with mock DB
- Frontend component tests (DeviceInventory, RiskScore, Loading, ErrorBoundary)
- Frontend API client tests (all endpoint functions, FormData upload)
- Frontend Login page tests
- Kubernetes manifests: Service, Ingress, HPA, NetworkPolicy, PVC, RBAC (7 manifests)
- CI/CD pipeline: GitHub Actions (lint, test, Trivy scan, CodeQL), Dependabot
- Docker HEALTHCHECK + non-root user on all 3 Dockerfiles
- `.dockerignore`, `Makefile`, `.editorconfig`, `.gitattributes`, `.golangci.yml`
- Community files: `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `LICENSE`, GitHub templates
- Architecture Decision Records: ADR-001 through ADR-009
- Changelog (this file)

### Changed
- Docker Compose: removed `network_mode: host`, added isolated `ironmesh-internal` bridge network
- Docker Compose: pinned all service versions (replaced `:latest` tags)
- Docker Compose: added healthchecks to all services, proper `depends_on` conditions
- `docker-compose.yml`: Grafana default password via `GRAFANA_PASSWORD` env var

### Fixed
- WebSocket `CheckOrigin` always true → origin whitelist via `ALLOWED_ORIGINS` env var
- WebSocket data race: `RLock` → `Lock` in `Broadcast()` method
- WebSocket moved to authenticated route group (now requires JWT)
- Type assertion panics in `ChangePasswordHandler` and `PermissionsHandler`
- `slog.Fatal` doesn't call `os.Exit(1)` → added `os.Exit(1)` after log output
- Default DB password hardcoded → removed, now requires `DATABASE_URL` env var
- CORS wide open (`*`) → origin matching against `ALLOWED_ORIGINS`
- Firmware upload path traversal via `header.Filename` → `filepath.Base()`
- Dead code in `ValidateFirmwareFile` → inverted logic, return error on unknown bytes
- Cert pinning `InsecureSkipVerify` (never set) → now uses `VerifyPeerCertificate` callback
- Custom `itoa` → replaced with `strconv.Itoa`
- Import paths: `github.com/yourusername/seagles` → `github.com/Nciibi/seagles`

### Security
- All Docker images now run as non-root user
- Read-only root filesystem on K8s deployments
- Pod Security Standards (restricted) applied to K8s manifests
- Network policies restrict pod-to-pod communication
- RBAC with least-privilege ServiceAccount

## [2.0.0] - 2026-07-01

### Added
- Initial release with IoT device discovery, scanning, vulnerability detection, firmware analysis, and risk scoring
- WebSocket real-time updates
- RBAC with 4 roles and 50+ granular permissions
- RS256 JWT with auto-generated or PEM-loaded 2048-bit RSA keys
- Circuit breaker pattern for external API calls
- Risk scoring engine (0-10) with CVSS, EPSS, KEV, exploit availability
- Prometheus metrics endpoint
- 13 database migrations
- Firmware analyzer microservice (Python/FastAPI)
- Certificate pinning infrastructure
- OpenAPI 3.0 spec
- Passive network monitoring (gopacket) + active scanning (nmap)
- PWA support with service worker
