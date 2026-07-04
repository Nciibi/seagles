# Development Setup

## Prerequisites

- Go 1.25+
- Node.js 22+
- Docker & Docker Compose
- Make (optional)

## Quick Start

```bash
# 1. Clone the repository
git clone <repo-url>
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

## Default Credentials

| Username | Password | Role |
|----------|----------|------|
| `admin` | `changeme` | admin |

**Important:** Change the password on first login via `POST /auth/change-password`.

## Environment Variables

See `.env.example` for all options. Key variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | postgres://... | PostgreSQL connection string |
| `JWT_SECRET` | No | auto-generated | RSA private key PEM |
| `JWT_PRIVATE_KEY_FILE` | No | — | Path to PEM file |
| `NETWORK_CIDR` | No | 192.168.1.0/24 | Scan target subnet |
| `RATE_LIMIT_PER_MIN` | No | 60 | Default rate limit |
| `LOG_LEVEL` | No | info | debug/info/warn/error |
| `REDIS_URL` | No | — | Redis for distributed caching |

## Makefile Commands

```bash
make up              # Start all services
make down            # Stop all services
make dev             # Start deps + run backend directly
make build-backend   # Compile Go binary
make build-frontend  # Build frontend
make test            # Run all backend tests
make vet             # Run go vet
make health          # Check API health
make login           # Test login endpoint
```

## Testing

### Backend Tests
```bash
cd backend
go test -v -count=1 ./...
```

### Run specific package
```bash
go test -v -count=1 ./auth/
```

### Run with race detection
```bash
go test -race ./...
```

### Integration Tests (requires Docker)
```bash
# Start test DB
docker compose up -d postgres
# Run tests pointing at test DB
DATABASE_URL=postgres://... go test -v ./api/
```

## Adding Migrations

Create a new file in `backend/db/migrations/` with sequential numbering:
```sql
-- 014_my_feature.sql
CREATE TABLE ...
CREATE INDEX ...
```

Migrations run automatically on startup in sorted order.

## Adding an API Endpoint

1. Create handler in `backend/api/` (or add to existing file)
2. Register route in `backend/api/router.go`
3. Add request/response types if needed
4. Add OpenAPI spec to `backend/api/swagger.json`
5. Add API docs in `docs/api.md`
6. Add permission check in `backend/auth/auth.go` (RolePermissions map)

## Building for Production

```bash
# Backend binary
cd backend && go build -o bin/ironmesh .

# Docker image
docker build -t ironmesh-backend:latest -f backend/Dockerfile backend/

# Frontend
cd frontend && npm run build
```
