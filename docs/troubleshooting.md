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
postgres://ironmesh:changeme_strong_password_here@localhost:5432/ironmesh?sslmode=disable
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
- Unauthenticated connections are rejected
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

**Cause:** RSA key pair was auto-generated and differs from previous instance.

**Fix:** Set `JWT_SECRET` or `JWT_PRIVATE_KEY_FILE` in `.env` to persist keys:
```bash
# Generate key
openssl genrsa -out jwt-private.pem 2048
# Reference in .env
JWT_PRIVATE_KEY_FILE=/path/to/jwt-private.pem
```

### Firmware upload: "Invalid firmware file"

**Cause:** File extension or magic bytes don't match known firmware formats.

**Valid extensions:** `.bin`, `.elf`, `.gz`, `.tar`, `.bz2`, `.xz`, `.zip`, `.rar`, `.7z`, `.img`, `.fw`, `.rom`, `.squashfs`, `.ubifs`, `.jffs2`, `.cramfs`

**Max size:** 256 MB

### Database connection pool exhausted

**Symptoms:** Slow responses, `timeout: connection pool exhausted`

**Check:**
```bash
# Current connections
docker compose exec postgres psql -U ironmesh -c "SELECT count(*) FROM pg_stat_activity WHERE datname = 'ironmesh';"
```

**Fix:** Lower `DB_MAX_OPEN_CONNS` or increase PostgreSQL `max_connections`.

### Redis connection errors

**Cause:** Redis is not running or `REDIS_URL` is misconfigured.

**Check:**
```bash
docker compose ps redis
docker compose logs redis
```

**Note:** Redis is optional. The system falls back to in-memory cache if Redis is unavailable.

### MinIO connection errors

**Cause:** MinIO is not running or credentials are wrong.

**Check:**
```bash
docker compose ps minio
docker compose logs minio
# Test MinIO health
curl http://localhost:9000/minio/health/live
```

**Fix:** Verify `S3_ACCESS_KEY` and `S3_SECRET_KEY` in `.env` match MinIO configuration.

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

### Firmware Analyzer not responding

**Cause:** The Python FastAPI service failed to start or crashed.

**Check:**
```bash
docker compose logs firmware-analyzer
# Test directly
curl http://localhost:8001/health
```

**Fix:** Ensure `DATABASE_URL` env var is set for the firmware-analyzer. The service may take 10-15 seconds to start due to dependency installation.

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

**Fix:** Clear browser cache and reload. If API is unreachable, check backend logs.

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
