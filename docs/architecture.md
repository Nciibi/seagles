# Architecture

## Overview

IronMesh is an IoT security platform that discovers devices on a network, scans them for vulnerabilities, analyzes firmware, and provides risk scoring. It consists of three main components:

```mermaid
graph TB
    subgraph "Frontend"
        React[React SPA<br/>Port 3000]
        SW[Service Worker<br/>PWA + Offline Cache]
    end

    subgraph "Backend"
        Gin[Go/Gin API Server<br/>Port 8080]
        WS[WebSocket Hub<br/>Real-time Events]
        Scanner[Scanner Engine<br/>nmap + libpcap]
        Risk[Risk Scorer<br/>CVSS + EPSS + KEV]
        Audit[Audit Logger]
    end

    subgraph "Microservices"
        FA[Firmware Analyzer<br/>Python/FastAPI<br/>Port 8001]
    end

    subgraph "Data Layer"
        PG[(PostgreSQL<br/>Devices, Scans, Vulns)]
        RD[(Redis<br/>Cache + Rate Limiter)]
        MO[(MinIO/S3<br/>Firmware Files)]
    end

    subgraph "Monitoring"
        PM[Prometheus<br/>Metrics]
        GF[Grafana<br/>Dashboards]
    end

    React -->|REST API| Gin
    React -->|WebSocket| WS
    Gin -->|Firmware Analysis| FA
    Gin -->|Persist| PG
    Gin -->|Cache| RD
    Gin -->|Store| MO
    PM -->|Scrape| Gin
    GF -->|Query| PM
    Scanner -->|nmap| Network{Target Network}
```

## Backend Architecture

```
backend/
├── main.go          # Entry point, graceful shutdown
├── api/             # HTTP handlers + router
│   ├── router.go    # Route definitions, middleware chain
│   ├── ws.go        # WebSocket hub + origin whitelist
│   ├── swagger.go   # OpenAPI docs endpoint
│   ├── handlers.go  # Devices, scans, vulns, alerts CRUD
│   ├── firmware.go  # Firmware upload + analysis
│   ├── safelist.go  # IP/MAC safe list management
│   ├── webhooks.go  # Webhook CRUD + test
│   ├── scopes.go    # Scan scope management
│   ├── profiles.go  # Scan profile CRUD
│   ├── users.go     # User management
│   └── health.go    # Health check + stats
├── auth/            # Authentication & authorization
│   ├── auth.go      # Handlers (login, register, refresh, logout)
│   ├── tokens.go    # RS256 JWT core
│   └── rbac.go      # Role/permission definitions
├── breaker/         # Circuit breaker for external APIs
├── cache/           # In-memory TTL cache + token blacklist
├── config/          # Environment config loading
├── db/              # Database connection + migrations
│   └── migrations/  # 13 SQL migration files
├── kev/             # CISA KEV + EPSS feed updaters
├── middleware/       # Cross-cutting concerns
│   ├── audit.go     # Audit logging for write ops
│   ├── ratelimit.go # Per-endpoint rate limiter
│   ├── sanitize.go  # XSS filtering, file validation
│   ├── tls.go       # TLS enforcement + cert pinning
│   └── metrics.go   # Prometheus metrics
├── models/          # Data models
├── risk/            # Risk scoring engine
├── scanner/         # Network scanning
│   ├── protocols.go # Protocol detection (Telnet, ADB, MQTT, etc.)
│   ├── credentials.go # Default credential testing
│   ├── tls.go       # TLS version/cipher detection
│   └── passive.go   # gopacket passive monitoring
├── slog/            # Structured logging
├── alerts/          # Alert engine + dedup
└── tests/           # Integration tests
```

### Middleware Chain

Requests flow through this pipeline:

```mermaid
graph LR
    A[Recovery] --> B[Request ID]
    B --> C[Security Headers]
    C --> D[CORS]
    D --> E[Body Limit]
    E --> F[Rate Limiter]
    F --> G[Sanitize]
    G --> H[Audit Log]
    H --> I[Route Handler]
```

### Authentication Flow

```mermaid
sequenceDiagram
    participant U as User/Browser
    participant F as Frontend
    participant B as Backend
    participant DB as PostgreSQL

    U->>F: Enter credentials
    F->>B: POST /auth/login
    B->>DB: Verify credentials
    DB-->>B: User found
    B-->>F: Access token (15m) + Refresh token (7d)
    F->>F: Store refresh in secure storage

    Note over F,B: Subsequent requests
    F->>B: GET /devices (Authorization: Bearer)
    B->>B: Verify JWT signature
    B-->>F: 200 OK

    Note over F,B: Token refresh flow
    F->>B: GET /devices (expired token)
    B-->>F: 401 Unauthorized
    F->>B: POST /auth/refresh
    B-->>F: New access + refresh token
    F->>B: Retry original request with new token
```

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
│   ├── components/      # Reusable components
│   │   ├── ErrorBoundary.tsx
│   │   ├── Loading.tsx
│   │   ├── DeviceInventory.tsx
│   │   ├── RiskScore.tsx
│   │   ├── AlertFeed.tsx
│   │   ├── FirmwarePanel.tsx
│   │   ├── VulnScanner.tsx
│   │   ├── NetworkMap.tsx
│   │   └── VirtualScroller.tsx
│   ├── test/            # Test setup
│   │   └── setup.ts     # jest-dom matchers
│   └── styles/          # CSS modules
├── public/
│   ├── sw.js            # Service Worker
│   └── manifest.json    # PWA manifest
├── vitest.config.ts     # Vitest configuration
└── vite.config.ts       # Vite configuration
```

## Firmware Analyzer

```
firmware-analyzer/
├── main.py       # FastAPI app with Pydantic v2 models
├── analyze.py    # Analysis logic (entropy, binwalk, decompile)
├── cve_lookup.py # CVE matching against firmware metadata
└── Dockerfile
```

## Network Architecture (Docker Compose)

```mermaid
graph TB
    subgraph "ironmesh-internal (172.20.0.0/16)"
        Backend[Backend<br/>:8080]
        Frontend[Frontend<br/>:80]
        FA[Firmware Analyzer<br/>:8001]
        Postgres[PostgreSQL<br/>:5432]
        PgB[PgBouncer<br/>:5432]
        Redis[Redis<br/>:6379]
        MinIO[MinIO<br/>:9000]
        Prom[Prometheus<br/>:9090]
        Grafana[Grafana<br/>:3000]

        Backend --> PgB
        Backend --> Redis
        Backend --> MinIO
        Backend --> FA
        Postgres --> PgB
        Prom --> Backend
        Grafana --> Prom
    end

    Internet --> Frontend
    Frontend --> Backend
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
| Origin whitelist (WS) | Prevents unauthorized WebSocket connections from unknown origins |
| Isolated Docker network | Removed `network_mode: host` for security isolation |
