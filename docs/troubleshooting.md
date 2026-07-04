# Troubleshooting Guide

## Common Issues

### "Failed to open database connection"

**Cause:** PostgreSQL is not running or credentials are incorrect.

**Check:**
```bash
docker compose ps postgres
docker compose logs postgres
```

**Fix:** Ensure `DATABASE_URL` in `.env` matches `docker-compose.yml`. Default:
```
postgres://ironmesh:changeme_strong_password_here@pgbouncer:5432/ironmesh?sslmode=disable
```

If using direct PostgreSQL connection (bypassing PgBouncer):
```
postgres://ironmesh:changeme_strong_password_here@postgres:5432/ironmesh
```

### "Rate limit exceeded" on login

**Cause:** Default rate limit is 60 req/min per IP. Login failures don't reset.

**Wait:** 1 minute for window reset.

**Fix:** Increase `RATE_LIMIT_PER_MIN` in `.env`. For dev, set to `600`.

### Token expired / "Invalid or expired token"

**Cause:** Access token TTL is 15 minutes (default).

**Fix:** The frontend auto-refreshes via `POST /auth/refresh`. If refresh fails:
- User needs to re-login
- Refresh token may have been revoked (password change, admin action)
- Admin can check active sessions via `GET /sessions`

### "Cannot find migrations directory"

**Cause:** Running from wrong working directory.

**Fix:** Run from `backend/`:
```bash
cd backend && go run .
```

### WebSocket disconnects

**Cause:** No `pong` response within 60 seconds, or network issue.

**Check:**
- `client.send` channel buffer (256) may be full
- Client must send `pong` within 60s of receiving `ping`
- Unauthenticated connections are rejected before upgrade
- Check `ALLOWED_ORIGINS` env var includes your frontend URL

**Fix:**
- Ensure WebSocket client sends `pong` on each `ping`
- Configure `ALLOWED_ORIGINS` (comma-separated) in `.env`

### KEV/EPSS errors in logs

**Cause:** External API is down or circuit breaker is open.

**Expected:** The system degrades gracefully:
- KEV: uses last cached catalog file
- EPSS: returns vulnerabilities without EPSS scores
- Circuit breaker auto-recovers after 30s (configurable)

### CORS errors in browser console

**Cause:** Browser is blocking cross-origin requests because the `Origin` header doesn't match the server's whitelist.

**Check:**
```bash
# Verify ALLOWED_ORIGINS is set
docker compose exec backend env | grep ALLOWED_ORIGINS
```

**Fix:** Set `ALLOWED_ORIGINS` in `.env` to your frontend URL:
```
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
```

### Auth fails after deployment

**Cause:** RSA key pair was auto-generated and differs from previous instance. All existing tokens are now invalid.

**Fix:** Set `JWT_SECRET` or `JWT_PRIVATE_KEY_FILE` in `.env` to persist keys:
```bash
# Generate key
openssl genrsa -out jwt-private.pem 2048
# Reference in .env
JWT_PRIVATE_KEY_FILE=/path/to/jwt-private.pem
```
Then restart the backend.

### Firmware upload: "Invalid firmware file"

**Cause:** File extension or magic bytes don't match known firmware formats.

**Valid extensions:** `.bin`, `.elf`, `.gz`, `.tar`, `.bz2`, `.xz`, `.zip`, `.rar`, `.7z`, `.img`, `.fw`, `.rom`, `.squashfs`, `.ubifs`, `.jffs2`, `.cramfs`

**Max size:** 256 MB

**Note:** The first 512 bytes are checked for magic byte signatures. If the file passes extension check but fails magic byte check, the file may be corrupted or renamed.

### Database connection pool exhausted

**Symptoms:** Slow responses, `timeout: connection pool exhausted`

**Check:**
```bash
# Current connections
docker compose exec postgres psql -U ironmesh -c "SELECT count(*) FROM pg_stat_activity WHERE datname = 'ironmesh';"
```

**Fix:** Lower `DB_MAX_OPEN_CONNS` or increase PostgreSQL `max_connections`. Alternatively, PgBouncer may need a larger pool size.

### Redis connection errors

**Cause:** Redis is not running or `REDIS_URL` is misconfigured.

**Check:**
```bash
docker compose ps redis
docker compose logs redis
```

**Note:** Redis is optional. The system falls back to in-memory cache if Redis is unavailable. Token blacklist, rate limiter, and data cache all work without Redis.

### MinIO connection errors

**Cause:** MinIO is not running or credentials are wrong.

**Check:**
```bash
docker compose ps minio
docker compose logs minio
# Test MinIO health
curl http://localhost:9000/minio/health/live
```

**Fix:** Verify `S3_ACCESS_KEY` and `S3_SECRET_KEY` in `.env` match MinIO configuration. Default:
- Access Key: `admin`
- Secret Key: `password123`

### PgBouncer errors

**Symptoms:** `could not connect to server: Connection refused`, `no pg_hba.conf entry`

**Check:**
```bash
docker compose logs pgbouncer
```

**Fix:** Ensure PostgreSQL is healthy before PgBouncer starts:
```bash
docker compose restart pgbouncer
```
If the backend connects directly to PostgreSQL (bypassing PgBouncer), ensure `DATABASE_URL` points to `postgres:5432` not `pgbouncer:5432`.

### Firmware Analyzer not responding

**Cause:** The Python FastAPI service failed to start or crashed.

**Check:**
```bash
docker compose logs firmware-analyzer
# Test directly
curl http://localhost:8001/health
```

**Fix:** Ensure `FIRMWARE_ANALYZER_URL` env var is set correctly. The service may take 10-15 seconds to start on first run due to Python dependency installation. On resource-constrained hosts, consider increasing the startup timeout.

### Frontend shows blank page

**Cause:** JavaScript error during load, or API unreachable.

**Check:**
```bash
# Browser dev console for errors
# Check API connectivity
curl http://localhost:8080/api/v1/health
# Check frontend is serving
curl http://localhost:3000
```

**Fix:** Clear browser cache and reload. If API is unreachable, check backend logs. If using a different port, ensure `ALLOWED_ORIGINS` includes the correct frontend URL.

### Grafana dashboards not showing data

**Cause:** Prometheus target unreachable or dashboards not loaded.

**Check:**
```bash
# Check Prometheus targets
curl http://localhost:9090/api/v1/targets
# Check Grafana datasource
curl http://localhost:3000/api/datasources
```

**Fix:** Ensure Prometheus is scraping the backend at `backend:8080/metrics`. Dashboards are loaded from `docker/grafana/dashboards/` via provisioning.

### Prometheus metrics not accessible

**Cause:** Backend metrics endpoint not exposed or blocked.

**Check:**
```bash
curl http://localhost:8080/api/v1/metrics
```

**Fix:** The metrics endpoint is public (no auth required). If behind a reverse proxy, ensure `/metrics` is not blocked.

### Docker Compose "service not found"

**Cause:** Running an older version of Docker Compose that doesn't support the v2 format.

**Fix:** Use `docker-compose` (with hyphen) instead of `docker compose`, or upgrade to Docker Compose v2+:
```bash
docker compose version
# If not found:
docker-compose up -d
```

### Makefile targets fail on Windows

**Cause:** Make is not available on Windows by default.

**Fix:** Use the individual commands instead:
```bash
# Instead of make build
cd backend && go build -o ironmesh .
cd frontend && npm run build

# Instead of make test
cd backend && go test -v -count=1 ./...
cd frontend && npm test
```
Or install Make via Chocolatey: `choco install make`

---

## Debug Mode

Enable debug logging:
```bash
LOG_LEVEL=debug docker compose up -d
```

Check specific request IDs in logs:
```bash
docker compose logs backend | grep <request-id>
```

---

## Health Check

```bash
curl http://localhost:8080/api/v1/health
```

Response:
```json
{
  "status": "ok",
  "service": "ironmesh-api",
  "version": "2.1.0",
  "db_ok": true
}
```

If `db_ok` is `false`, the DB health monitor has detected connectivity issues and is attempting to reconnect (5 retries, 2s apart).

---

## Container Status

Check all services:
```bash
docker compose ps
docker compose logs --tail=50
```

Check resource usage:
```bash
docker stats
```

---

## Kubernetes

### Pod not starting
```bash
kubectl describe pod -n security-tools -l app=seagles-backend
kubectl logs -n security-tools -l app=seagles-backend
```

### Secrets not found
```bash
kubectl get secrets -n security-tools
kubectl describe secret seagles-db-secrets -n security-tools
```

### Ingress not working
```bash
kubectl describe ingress seagles-ingress -n security-tools
kubectl get events -n security-tools
```

### HPA not scaling
```bash
kubectl describe hpa seagles-hpa -n security-tools
kubectl top pods -n security-tools
```

### Network policy blocking traffic
```bash
kubectl describe networkpolicy -n security-tools
kubetl logs -n security-tools -l app=seagles-backend --tail=50
```
