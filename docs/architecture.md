# Architecture

## Overview

IronMesh is an IoT security platform that discovers devices on a network, scans them for vulnerabilities, analyzes firmware, and provides risk scoring. It consists of three main components:

```
┌─────────────┐     ┌──────────────┐     ┌───────────────────┐
│  Frontend   │────▶│   Backend    │────▶│  Firmware Analyzer│
│  (React SPA)│     │  (Go/Gin)    │     │  (FastAPI/Python) │
└─────────────┘     └──────┬───────┘     └───────────────────┘
                           │
                    ┌──────┴───────┐
                    │  PostgreSQL  │
                    └──────────────┘
```

## Backend Architecture

```
backend/
├── main.go          # Entry point, graceful shutdown
├── api/             # HTTP handlers + router
│   ├── router.go    # Route definitions, middleware chain
│   ├── ws.go        # WebSocket hub
│   ├── swagger.go   # OpenAPI docs
│   └── *.go         # Per-resource handlers
├── auth/            # Authentication & authorization
│   ├── auth.go      # Handlers (login, register, refresh, logout)
│   ├── tokens.go    # RS256 JWT core
│   └── rbac.go      # Role/permission definitions (in auth.go)
├── breaker/         # Circuit breaker for external APIs
├── cache/           # In-memory TTL cache + token blacklist
├── config/          # Environment config loading
├── db/              # Database connection + migrations
├── kev/             # CISA KEV + EPSS feed updaters
├── middleware/       # Cross-cutting concerns
│   ├── sanitize.go  # XSS filtering, file validation
│   ├── ratelimit.go # Per-endpoint rate limiter
│   ├── audit.go     # Audit logging for write ops
│   └── csrf.go      # CSRF token utility
├── models/          # Data models
├── risk/            # Risk scoring engine
├── scanner/         # Network scanning (nmap, TLS, creds, protocols)
└── slog/            # Structured logging
```

### Middleware Chain

Requests flow through this pipeline:

```
Recovery → Request ID → Security Headers → CORS → Body Limit → Rate Limiter → Sanitize → Audit Log → Route Handler
```

### Authentication Flow

1. User logs in → receives access token (15m) + refresh token (7d)
2. Client stores refresh token securely, sends access token as `Authorization: Bearer`
3. On 401, client transparently refreshes via `POST /auth/refresh`
4. On logout, access token is blacklisted (prevents reuse for 15m)
5. On password change, all refresh tokens are revoked

## Frontend Architecture

```
frontend/
├── src/
│   ├── main.tsx         # Entry point + PWA registration
│   ├── App.tsx          # Layout, routing, logout
│   ├── api/client.ts    # Axios client + refresh interceptor
│   ├── pages/           # Route-level components
│   │   ├── Dashboard.tsx
│   │   ├── Login.tsx
│   │   ├── Devices.tsx
│   │   ├── DeviceDetail.tsx
│   │   ├── Vulnerabilities.tsx
│   │   ├── Alerts.tsx
│   │   ├── Firmware.tsx
│   │   └── Settings.tsx
│   └── components/      # Reusable components
│       ├── ErrorBoundary.tsx
│       ├── Loading.tsx
│       └── VirtualScroller.tsx
├── public/
│   ├── sw.js            # Service Worker
│   └── manifest.json    # PWA manifest
```

## Firmware Analyzer

```
firmware-analyzer/
├── main.py       # FastAPI app with Pydantic v2 models
├── analyze.py    # Analysis logic (entropy, binwalk, decompile)
└── Dockerfile
```

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| RS256 JWT | Asymmetric keys allow public key distribution without exposing private key |
| Refresh tokens in DB | Allows server-side revocation (password change, admin force-logout) |
| In-memory cache | Zero external dependency; swap to Redis is one-line change |
| Circuit breaker | Prevents cascading failure when CISA/EPSS/NVD APIs are down |
| Worker pool (20) | Controls resource usage during network scans |
| DB health monitor | Auto-reconnect prevents permanent loss of DB connectivity |
| Audit logging | All write ops logged for compliance and incident response |
