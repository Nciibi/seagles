# Setup Guide

## Prerequisites

- Go 1.22+
- Node.js 20+
- Docker & Docker Compose v2+
- Make (optional, for Makefile targets)

---

## Quick Start (Linux / macOS)

```bash
# 1. Clone the repository
git clone https://github.com/Nciibi/seagles
cd seagles

# 2. Copy environment config
cp .env.example .env
# Edit .env: set your network CIDR (e.g. 192.168.1.0/24)

# 3. Start all services
docker compose up -d

# 4. Open browser
open http://localhost:3000

# Default credentials: admin / changeme
```

---

## Quick Start (Windows)

### Prerequisites

- [Docker Desktop for Windows](https://docs.docker.com/desktop/install/windows-install/) with WSL2 backend
- [Go](https://go.dev/dl/) 1.22+
- [Node.js](https://nodejs.org/) 20+
- PowerShell 5.1+ or PowerShell Core

### Scaffold Script (Recommended)

```powershell
.\scaffold.ps1
```

This script handles: environment file setup, configuration prompts, Docker Desktop checks.

### Manual Steps

```powershell
# 1. Clone the repository
git clone https://github.com/Nciibi/seagles
cd seagles

# 2. Copy environment config
Copy-Item .env.example .env
# Edit .env: set your network CIDR (e.g. 192.168.1.0/24)

# 3. Start all services (Docker Desktop must be running)
docker compose up -d

# 4. Open browser
start http://localhost:3000
```

### Windows-Specific Notes

- **Linux containers mode** must be enabled in Docker Desktop (right-click tray icon → "Switch to Linux containers")
- If `docker compose` command is not found, use `docker-compose` (with hyphen)
- For full nmap scanner functionality, use a Linux VM or WSL2. Basic scanning works on Windows but `network_mode: host` behaves differently
- File sharing: ensure `C:\` is shared in Docker Desktop Settings → Resources → File Sharing
- PowerShell execution policy: if you see script execution errors, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

---

## Makefile Usage

```bash
make help          # List all targets
make all           # Lint + test + build
make build         # Build backend binary + frontend bundle
make test          # Run all tests
make lint          # Run all linters
make docker-build  # Build all Docker images
make docker-up     # Start Docker Compose services
make docker-down   # Stop all services
make security-scan # Run Trivy vulnerability scan
make clean         # Remove build artifacts
```

---

## Manual Setup (Without Docker)

```bash
# 1. Clone the repository
git clone https://github.com/Nciibi/seagles
cd seagles

# 2. Copy environment config
cp .env.example .env

# 3. Start infrastructure (PostgreSQL, Redis, MinIO)
docker compose up -d postgres redis minio

# 4. Run database migrations + start backend
cd backend
cp ../.env.example .env
go run .

# 5. In another terminal, start frontend
cd frontend
npm install
npm run dev
```

The API will be available at `http://localhost:8080` and the frontend at `http://localhost:5173`.

---

## Default Credentials

| Username | Password | Role |
|---|---|---|
| `admin` | `changeme` | admin |

**Important:** Change the password on first login via `POST /auth/change-password` or the Settings page.

---

## Environment Variables

See `.env.example` for the complete list. Key variables:

| Variable | Required | Default | Description |
|---|---|---|---|
| `DB_PASSWORD` | Yes | `changeme_strong_password_here` | PostgreSQL password |
| `NETWORK_CIDR` | No | `192.168.1.0/24` | Target subnet for network scan |
| `JWT_SECRET` | No | auto-generated | RSA private key PEM string |
| `JWT_PRIVATE_KEY_FILE` | No | — | Path to PEM private key file |
| `ALLOWED_ORIGINS` | No | `http://localhost:3000` | Comma-separated CORS/WS origins |
| `RATE_LIMIT_PER_MIN` | No | `60` | Default rate limit per IP |
| `LOG_LEVEL` | No | `info` | `debug`, `info`, `warn`, `error` |
| `SCAN_MAX_CONCURRENT` | No | `20` | Max concurrent network scans |
| `REDIS_URL` | No | — | Redis connection string (optional, falls back to in-memory cache) |
| `NVD_API_KEY` | No | — | NIST NVD API key (free at nvd.nist.gov) |
| `SLACK_WEBHOOK_URL` | No | — | Slack webhook for alerts |
| `TEAMS_WEBHOOK_URL` | No | — | Microsoft Teams webhook |
| `S3_ENDPOINT` | No | `minio:9000` | S3-compatible storage endpoint |
| `S3_BUCKET` | No | `seagles-firmware` | S3 bucket for firmware files |
| `S3_ACCESS_KEY` | No | `admin` | S3 access key |
| `S3_SECRET_KEY` | No | `password123` | S3 secret key |
| `DB_MAX_OPEN_CONNS` | No | `25` | Max open database connections |
| `DB_MAX_IDLE_CONNS` | No | `5` | Max idle database connections |
| `DB_CONN_MAX_LIFETIME_MINUTES` | No | `5` | Max connection lifetime |
| `GRAFANA_PASSWORD` | No | `admin` | Grafana admin password |

---

## Frontend Proxy Configuration

When running the frontend in development mode (`npm run dev`), the Vite dev server proxies API requests to the backend:

```typescript
// vite.config.ts
proxy: {
  '/api': {
    target: 'http://localhost:8080',
    changeOrigin: true,
  },
}
```

In production (Docker), the nginx container handles this proxy instead.

---

## MinIO Configuration

MinIO is used as S3-compatible storage for firmware uploads. Default access:

- **Console URL:** `http://localhost:9001`
- **API URL:** `http://localhost:9000`
- **Access Key:** `admin` (configurable via `S3_ACCESS_KEY`)
- **Secret Key:** `password123` (configurable via `S3_SECRET_KEY`)

If the default `seagles-firmware` bucket does not exist, it is created automatically on first firmware upload.

---

## PgBouncer Configuration

PgBouncer provides connection pooling for PostgreSQL. Default settings:

| Setting | Value |
|---|---|
| Max client connections | 1000 |
| Default pool size | 20 |
| Pool mode | Transaction |

The backend connects to PgBouncer:

```
postgres://seagles:${DB_PASSWORD}@pgbouncer:5432/seagles?sslmode=disable
```

To bypass PgBouncer (e.g., for running migrations directly), connect to PostgreSQL directly:

```
postgres://seagles:${DB_PASSWORD}@postgres:5432/seagles
```

---

## Monitoring Stack

Grafana dashboards are pre-configured in `docker/grafana/dashboards/`:

| Dashboard | Description |
|---|---|
| `security-overview.json` | Risk scores, vulnerability trends, alert counts |
| `device-health.json` | Device status, scan history, uptime |
| `scan-performance.json` | Scan duration, port counts, success rates |
| `audit-trail.json` | Audit log volume, user activity, error rates |

Prometheus configuration is at `docker/prometheus/prometheus.yml`. Metrics are exposed at `GET /metrics` on the backend.

---

## Kubernetes Deployment

Production-ready manifests are in `k8s/`:

| Manifest | Purpose |
|---|---|
| `seagles-backend-deployment.yaml` | Backend API deployment (2 replicas) |
| `seagles-frontend-deployment.yaml` | Frontend nginx deployment (2 replicas) |
| `seagles-service.yaml` | ClusterIP services for backend + frontend |
| `seagles-ingress.yaml` | HTTPS ingress with TLS |
| `seagles-hpa.yaml` | Horizontal Pod Autoscaler (CPU > 70%) |
| `seagles-network-policy.yaml` | Pod isolation, deny-all default |
| `seagles-pvc.yaml` | Persistent volume claims for PostgreSQL |
| `seagles-rbac.yaml` | Least-privilege ServiceAccount + Role |

```bash
kubectl create namespace security-tools
kubectl apply -f k8s/
```

**Note:** Update image tags and registry URLs in the manifests before deploying.

---

## Deploy Script

The `deploy.sh` script automates production deployment:

```bash
./deploy.sh
```

It builds the backend binary, installs frontend dependencies and builds the bundle, runs database migrations, then copies assets.

---

## Testing

### Backend Tests

```bash
# All tests
cd backend && go test -v -count=1 ./...

# Specific package
cd backend && go test -v -count=1 ./auth/

# With race detection
cd backend && go test -race ./...

# Benchmarks
cd backend && go test -bench=. ./...
```

### Frontend Tests

```bash
cd frontend && npm test

# Watch mode
cd frontend && npm run test:watch
```

### Integration Tests

```bash
# Start test DB
docker compose up -d postgres

# Run tests pointing at test DB
DATABASE_URL=postgres://seagles:password@localhost:5432/seagles?sslmode=disable go test -v ./api/
```

---

## Adding Migrations

Create a new file in `backend/db/migrations/` with sequential numbering:

```sql
-- 014_my_feature.sql
CREATE TABLE ...
CREATE INDEX ...
```

Migrations run automatically on startup in sorted order.

---

## Adding an API Endpoint

1. Create handler in `backend/api/` (or add to existing file)
2. Register route in `backend/api/router.go`
3. Add request/response types if needed
4. Add OpenAPI spec to `backend/api/swagger.go`
5. Add API docs in `docs/api.md`
6. Add permission check in `backend/auth/auth.go` (RolePermissions map)
7. Add audit logging if it's a write operation

---

## Building for Production

```bash
# Docker images
make docker-build

# Or build individually:
docker build -t seagles-backend:latest -f backend/Dockerfile backend/
docker build -t seagles-frontend:latest -f frontend/Dockerfile frontend/

# Backend binary (without Docker)
cd backend && go build -o seagles .

# Frontend (without Docker)
cd frontend && npm run build
```
