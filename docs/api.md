# Seagles API Documentation

Base URL: `/api/v1`

## Authentication

All protected endpoints require a Bearer token in the `Authorization` header.  
Tokens are obtained via `POST /auth/login`.

### Token Types

| Token | TTL | Storage | Usage |
|---|---|---|---|
| Access Token | 15 min | Client memory | `Authorization: Bearer <token>` |
| Refresh Token | 7 days | Secure storage (httpOnly cookie) | `POST /auth/refresh` |

### Token Rotation
- Refresh tokens are rotated on each use (old token invalidated)
- Password change invalidates ALL refresh tokens for the user
- Logout blacklists the current access token (15 min residual)
- Sessions list shows all active sessions; admins can revoke remotely

---

## Response Envelope

All endpoints return a uniform envelope:

```json
{
  "data": <payload> | null,
  "error": <string> | null
}
```

### HTTP Status Codes

| Code | Meaning |
|---|---|
| 200 | Success |
| 201 | Created |
| 400 | Bad request (validation error) |
| 401 | Unauthorized (missing/invalid token) |
| 403 | Forbidden (insufficient permissions) |
| 404 | Not found |
| 409 | Conflict (duplicate entry) |
| 413 | Request too large |
| 429 | Rate limit exceeded |
| 500 | Internal server error |

### Common Error Responses

```json
// 400 — Validation error
{ "data": null, "error": "Invalid request body: username is required" }

// 401 — Missing or invalid token
{ "data": null, "error": "Missing or invalid authentication token" }

// 403 — Insufficient permissions
{ "data": null, "error": "Insufficient permissions: admin role required" }

// 404 — Resource not found
{ "data": null, "error": "Device not found" }
```

### Pagination

List endpoints support cursor-based pagination via query parameters:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `page` | int | `1` | Page number (1-indexed) |
| `per_page` | int | `20` | Items per page (max 100) |

Pagination metadata is returned in response headers:

| Header | Description |
|---|---|
| `X-Total-Count` | Total number of items |
| `X-Page` | Current page |
| `X-Per-Page` | Items per page |

### Filtering

List endpoints support query parameter filtering:

| Parameter | Type | Description |
|---|---|---|
| `search` | string | Full-text search across name/description |
| `sort` | string | Field to sort by (prefix `-` for desc: `-risk_score`) |
| `severity` | string | Filter by severity: `critical`, `high`, `medium`, `low` |
| `status` | string | Filter by status: `active`, `resolved`, `acknowledged` |
| `device_id` | string | Filter by device UUID |
| `alert_type` | string | Filter by alert type constant |
| `is_kev` | bool | Filter by CISA KEV status (`true`/`false`) |
| `is_resolved` | bool | Filter by resolved status (`true`/`false`) |
| `is_acknowledged` | bool | Filter by acknowledged status (`true`/`false`) |
| `start_date` | string | ISO 8601 date range start |
| `end_date` | string | ISO 8601 date range end |

---

## Rate Limiting

Rate limit headers are returned on every response:

| Header | Description |
|---|---|
| `X-RateLimit-Limit` | Max requests per window |
| `X-RateLimit-Remaining` | Requests remaining in current window |
| `X-RateLimit-Reset` | Unix timestamp when window resets |

Default: 60 requests per minute per IP. Per-endpoint rules may apply.

---

## RBAC Permissions

| Role | Level | Description |
|---|---|---|
| `viewer` | 0 | Read-only access to devices, scans, vulnerabilities, alerts, firmware |
| `auditor` | 1 | Same as viewer + audit log access |
| `operator` | 2 | Full CRUD on devices, scans, vulnerabilities, alerts, firmware |
| `admin` | 3 | All permissions including user management, admin functions, webhook management |

Permissions follow the pattern `<resource>:<action>`. Admins get `<resource>:*` wildcards.

### Permission Matrix

| Endpoint | viewer | auditor | operator | admin |
|---|---|---|---|---|
| GET /devices | ✓ | ✓ | ✓ | ✓ |
| GET /devices/:id | ✓ | ✓ | ✓ | ✓ |
| DELETE /devices/:id | ✗ | ✗ | ✗ | ✓ |
| POST /devices/:id/scan | ✗ | ✗ | ✗ | ✓ |
| GET /devices/:id/risk-breakdown | ✓ | ✓ | ✓ | ✓ |
| GET /scans | ✓ | ✓ | ✓ | ✓ |
| GET /scans/:id | ✓ | ✓ | ✓ | ✓ |
| POST /scan/network | ✗ | ✗ | ✗ | ✓ |
| GET /vulnerabilities | ✓ | ✓ | ✓ | ✓ |
| PATCH /vulnerabilities/:id/resolve | ✗ | ✗ | ✓ | ✓ |
| GET /firmware | ✓ | ✓ | ✓ | ✓ |
| POST /firmware/:id/analyze | ✗ | ✗ | ✗ | ✓ |
| POST /firmware/upload | ✗ | ✗ | ✗ | ✓ |
| GET /alerts | ✓ | ✓ | ✓ | ✓ |
| POST /alerts/:id/ack | ✓ | ✓ | ✓ | ✓ |
| GET /webhooks | ✗ | ✗ | ✗ | ✓ |
| POST /webhooks | ✗ | ✗ | ✗ | ✓ |
| DELETE /webhooks/:id | ✗ | ✗ | ✗ | ✓ |
| POST /webhooks/:id/test | ✗ | ✗ | ✗ | ✓ |
| GET /users | ✗ | ✗ | ✗ | ✓ |
| POST /users | ✗ | ✗ | ✗ | ✓ |
| GET /audit-log | ✗ | ✓ | ✓ | ✓ |
| GET /safelists | ✓ | ✓ | ✓ | ✓ |
| POST /safelists | ✗ | ✗ | ✗ | ✓ |
| DELETE /safelists/:id | ✗ | ✗ | ✗ | ✓ |
| GET /scan-profiles | ✓ | ✓ | ✓ | ✓ |
| GET /scan-scopes | ✓ | ✓ | ✓ | ✓ |
| POST /scan-scopes | ✗ | ✗ | ✗ | ✓ |
| DELETE /scan-scopes/:id | ✗ | ✗ | ✗ | ✓ |
| GET /sessions | ✗ | ✗ | ✗ | ✓ |
| DELETE /sessions/:id | ✗ | ✗ | ✗ | ✓ |
| GET /stats | ✓ | ✓ | ✓ | ✓ |
| GET /health | Public | Public | Public | Public |
| GET /kev/status | ✓ | ✓ | ✓ | ✓ |
| GET /metrics | Public | Public | Public | Public |
| GET /swagger.json | Public | Public | Public | Public |
| GET /docs | Public | Public | Public | Public |
| WebSocket /ws | ✓ | ✓ | ✓ | ✓ |

---

## Endpoints

### Auth

#### `POST /auth/login`
Authenticate with username/password.

**Request**
```json
{
  "username": "admin",
  "password": "changeme"
}
```

**Response** `200 OK`
```json
{
  "data": {
    "token": "eyJhbGciOiJSUzI1NiIs...",
    "expires_in": 900,
    "refresh_token": "<tokenID>.<userID>",
    "user": {
      "id": "uuid",
      "username": "admin",
      "email": "admin@ironmesh.local",
      "role": "admin"
    }
  },
  "error": null
}
```

**Errors:** `400` — missing/invalid fields, `401` — wrong credentials

#### `POST /auth/refresh`
Exchange a refresh token for a new access + refresh token pair.

**Request**
```json
{
  "refresh_token": "<tokenID>.<userID>"
}
```

**Response** `200 OK`
```json
{
  "data": {
    "token": "<new access token>",
    "expires_in": 900,
    "refresh_token": "<new refresh token>"
  },
  "error": null
}
```

**Errors:** `401` — invalid/expired refresh token

#### `POST /auth/logout` (Protected)
Blacklists current access token.

**Headers:** `Authorization: Bearer <token>`

**Response** `200 OK`
```json
{
  "data": "Logged out successfully",
  "error": null
}
```

#### `POST /auth/change-password` (Protected)
Changes password and invalidates all refresh tokens.

**Headers:** `Authorization: Bearer <token>`

**Request**
```json
{
  "current_password": "oldpw",
  "new_password": "newpw12345"
}
```

**Response** `200 OK`
```json
{
  "data": "Password changed successfully. All sessions have been invalidated.",
  "error": null
}
```

**Errors:** `400` — weak password, `401` — wrong current password

#### `GET /auth/me` (Protected)
Returns current user info.

**Response** `200 OK`
```json
{
  "data": {
    "id": "uuid",
    "username": "admin",
    "email": "admin@ironmesh.local",
    "role": "admin"
  },
  "error": null
}
```

#### `GET /auth/permissions` (Protected)
Returns the role, permission list, and hierarchy level for the current user.

**Response** `200 OK`
```json
{
  "data": {
    "role": "admin",
    "level": 3,
    "permissions": ["devices:*", "scans:*", "vulnerabilities:*", "alerts:*", "firmware:*", "users:*", "settings:*"]
  },
  "error": null
}
```

---

### Devices

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/devices` | Authenticated | List all devices (paginated, filterable) |
| GET | `/devices/:id` | Authenticated | Get device details with latest scan and open vulns |
| DELETE | `/devices/:id` | Operator+ | Delete a device |
| POST | `/devices/:id/scan` | Operator+ | Trigger scan on specific device |
| GET | `/devices/:id/risk-breakdown` | Authenticated | Get risk score breakdown |

**Query Parameters (GET /devices):**
| Param | Type | Description |
|-------|------|-------------|
| `page` | int | Page number (default: 1) |
| `per_page` | int | Items per page (default: 20, max: 100) |
| `search` | string | Search by IP, hostname, vendor, MAC |
| `sort` | string | Sort field (prefix `-` for desc: `-risk_score`) |
| `device_type` | string | Filter by device type |

**Response (GET /devices):**
```json
{
  "data": [
    {
      "id": "uuid",
      "ip_address": "192.168.1.42",
      "mac_address": "aa:bb:cc:dd:ee:ff",
      "hostname": "camera-01",
      "vendor": "Hikvision",
      "device_type": "camera",
      "os_fingerprint": "Linux 4.19",
      "firmware_version": "v5.4.3",
      "first_seen": "2026-07-01T10:00:00Z",
      "last_seen": "2026-07-04T14:30:00Z",
      "risk_score": 8.5,
      "is_active": true,
      "tags": ["production", "camera"]
    }
  ],
  "error": null
}
```

---

### Scans

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/scans` | Authenticated | List all scans |
| GET | `/scans/:id` | Authenticated | Get scan details |
| POST | `/scan/network` | Operator+ | Trigger network-wide scan |

**Response (GET /scans):**
```json
{
  "data": [
    {
      "id": "uuid",
      "device_id": "uuid | null",
      "started_at": "2026-07-04T12:00:00Z",
      "completed_at": "2026-07-04T12:05:00Z | null",
      "status": "completed",
      "scan_type": "full",
      "open_ports": [22, 80, 443, 554, 1883, 502],
      "services": {
        "22": "SSH",
        "80": "HTTP",
        "443": "HTTPS",
        "554": "RTSP",
        "1883": "MQTT",
        "502": "Modbus"
      }
    }
  ],
  "error": null
}
```

**Scan status values:** `pending`, `running`, `completed`, `failed`

---

### Vulnerabilities

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/vulnerabilities` | Authenticated | List vulnerabilities (filterable) |
| PATCH | `/vulnerabilities/:id/resolve` | Operator+ | Mark vulnerability as resolved |

**Query Parameters (GET /vulnerabilities):**
| Param | Type | Description |
|-------|------|-------------|
| `page` | int | Page number |
| `per_page` | int | Items per page |
| `severity` | string | `critical`, `high`, `medium`, `low` |
| `is_kev` | bool | CISA KEV status |
| `is_resolved` | bool | Resolved status |
| `device_id` | string | Filter by device |

**Response:**
```json
{
  "data": [
    {
      "id": "uuid",
      "device_id": "uuid",
      "scan_id": "uuid",
      "cve_id": "CVE-2024-7029",
      "cvss_score": 9.8,
      "severity": "critical",
      "title": "AVTECH Camera Default Credentials",
      "description": "Camera uses default admin/admin credentials",
      "affected_component": "Web interface",
      "remediation": "Change password via admin panel",
      "is_kev": true,
      "epss_score": 0.97,
      "epss_percentile": 0.99,
      "discovered_at": "2026-07-04T12:00:00Z",
      "resolved_at": null,
      "is_resolved": false
    }
  ],
  "error": null
}
```

---

### Alerts

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/alerts` | Authenticated | List alerts (filterable) |
| POST | `/alerts/:id/ack` | Authenticated | Acknowledge an alert |

**Query Parameters (GET /alerts):**
| Param | Type | Description |
|-------|------|-------------|
| `page` | int | Page number |
| `per_page` | int | Items per page |
| `severity` | string | `critical`, `high`, `medium`, `low` |
| `alert_type` | string | Alert type constant |
| `is_acknowledged` | bool | Acknowledged status |
| `device_id` | string | Filter by device |

**Alert types:** `default_creds`, `telnet_exposed`, `adb_exposed`, `modbus_detected`, `rtsp_unauthenticated`, `weak_tls`, `mqtt_plaintext`, `firmware_anomaly`, `kev_match`

**Response:**
```json
{
  "data": [
    {
      "id": "uuid",
      "device_id": "uuid",
      "severity": "critical",
      "alert_type": "default_creds",
      "title": "Default credentials found on camera-01",
      "description": "Admin/admin credentials work on device 192.168.1.42",
      "triggered_at": "2026-07-04T12:00:00Z",
      "acknowledged_at": null,
      "is_acknowledged": false,
      "metadata": {
        "port": 80,
        "protocol": "HTTP",
        "username": "admin",
        "evidence": "HTTP 200 with admin panel"
      }
    }
  ],
  "error": null
}
```

---

### Firmware

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/firmware` | Authenticated | List firmware entries |
| POST | `/firmware/:id/analyze` | Operator+ | Trigger firmware analysis |
| POST | `/firmware/upload` | Operator+ | Upload firmware file |

**Upload constraints:**
- Max file size: 256 MB
- Valid extensions: `.bin`, `.elf`, `.gz`, `.tar`, `.bz2`, `.xz`, `.zip`, `.rar`, `.7z`, `.img`, `.fw`, `.rom`, `.squashfs`, `.ubifs`, `.jffs2`, `.cramfs`
- Magic byte verification performed on upload

**Response (GET /firmware):**
```json
{
  "data": [
    {
      "id": "uuid",
      "device_id": "uuid",
      "version": "v5.4.3",
      "vendor": "Hikvision",
      "entropy_score": 7.5,
      "has_default_creds": true,
      "has_telnet": true,
      "has_backdoor_indicators": false,
      "strings_of_interest": ["admin", "root", "debug"],
      "cve_matches": ["CVE-2024-7029"],
      "analysis_status": "completed",
      "analyzed_at": "2026-07-04T12:05:00Z"
    }
  ],
  "error": null
}
```

---

### Webhooks

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/webhooks` | Operator+ | List webhooks |
| POST | `/webhooks` | Operator+ | Create webhook |
| DELETE | `/webhooks/:id` | Operator+ | Delete webhook |
| POST | `/webhooks/:id/test` | Operator+ | Test webhook delivery |

**Request (POST /webhooks):**
```json
{
  "name": "Slack Alerts",
  "url": "https://hooks.slack.com/services/...",
  "webhook_type": "slack",
  "min_severity": "high"
}
```

**Supported types:** `slack`, `teams`, `syslog`, `generic`

**Response:**
```json
{
  "data": {
    "id": "uuid",
    "name": "Slack Alerts",
    "url": "https://hooks.slack.com/services/...",
    "webhook_type": "slack",
    "min_severity": "high",
    "is_active": true,
    "last_triggered": null
  },
  "error": null
}
```

---

### Safelists

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/safelists` | Authenticated | List safelist entries |
| POST | `/safelists` | Operator+ | Create safelist entry |
| DELETE | `/safelists/:id` | Operator+ | Delete safelist entry |

**Request (POST /safelists):**
```json
{
  "entry_type": "ip_address",
  "value": "192.168.1.100",
  "reason": "Known management server"
}
```

**Entry types:** `ip_address`, `mac_address`, `cidr`

**Response:**
```json
{
  "data": {
    "id": "uuid",
    "entry_type": "ip_address",
    "value": "192.168.1.100",
    "reason": "Known management server",
    "created_at": "2026-07-04T12:00:00Z",
    "is_active": true
  },
  "error": null
}
```

---

### Scan Scopes

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/scan-scopes` | Authenticated | List scan scopes |
| POST | `/scan-scopes` | Operator+ | Create scan scope |
| DELETE | `/scan-scopes/:id` | Operator+ | Delete scan scope |

**Request (POST /scan-scopes):**
```json
{
  "cidr": "10.0.1.0/24",
  "label": "DMZ Network"
}
```

**Response:**
```json
{
  "data": {
    "id": "uuid",
    "cidr": "10.0.1.0/24",
    "label": "DMZ Network",
    "is_active": true
  },
  "error": null
}
```

---

### Scan Profiles

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/scan-profiles` | Authenticated | List scan profiles |

**Response:**
```json
{
  "data": [
    {
      "id": "uuid",
      "name": "Quick Scan",
      "description": "Fast port scan with credential testing",
      "skip_credential_test": false,
      "skip_protocol_probe": false,
      "max_port_count": 100,
      "timeout_seconds": 300,
      "is_default": true
    }
  ],
  "error": null
}
```

---

### Users

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/users` | Admin | List all users |
| POST | `/users` | Admin | Create new user |

**Request (POST /users):**
```json
{
  "username": "jdoe",
  "email": "jdoe@company.com",
  "password": "securepass123",
  "role": "operator"
}
```

---

### Sessions

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/sessions` | Admin | List all active sessions |
| DELETE | `/sessions/:id` | Admin | Revoke a session |

**Response (GET /sessions):**
```json
{
  "data": [
    {
      "id": "uuid",
      "user_id": "uuid",
      "username": "admin",
      "ip_address": "192.168.1.10",
      "user_agent": "Mozilla/5.0...",
      "last_activity": "2026-07-04T14:30:00Z",
      "created_at": "2026-07-04T10:00:00Z",
      "is_current": true
    }
  ],
  "error": null
}
```

---

### Audit Log

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/audit-log` | Auditor+ | List audit log entries |

**Response:**
```json
{
  "data": [
    {
      "id": "uuid",
      "user_id": "uuid",
      "username": "admin",
      "action": "delete",
      "resource": "/devices/uuid",
      "ip_address": "192.168.1.10",
      "user_agent": "Mozilla/5.0...",
      "status_code": 200,
      "latency_ms": 45,
      "created_at": "2026-07-04T12:00:00Z"
    }
  ],
  "error": null
}
```

---

### Dashboard / Stats

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | Public | Health check — returns DB + service status |
| GET | `/stats` | Authenticated | Dashboard statistics (counts, averages) |
| GET | `/kev/status` | Authenticated | CISA KEV catalog update status |

**Response (GET /stats):**
```json
{
  "data": {
    "total_devices": 150,
    "online_devices": 120,
    "avg_risk_score": 4.2,
    "critical_vulns": 12,
    "high_vulns": 28,
    "medium_vulns": 45,
    "kev_vulns": 5,
    "open_alerts": 18,
    "suspicious_firmware": 3
  },
  "error": null
}
```

### Public Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check — returns DB + service status |
| GET | `/metrics` | Prometheus metrics endpoint |
| GET | `/swagger.json` | OpenAPI 3.0 specification |
| GET | `/docs` | Swagger UI documentation explorer |

**Response (GET /swagger.json):**
```json
{
  "openapi": "3.0.3",
  "info": {
    "title": "Seagles API",
    "version": "2.1.0"
  },
  "paths": {
    ...
  }
}
```

---

## WebSocket

Connect to `wss://<host>/api/v1/ws` with the same Bearer token in the `Authorization` header.

### WebSocket Handshake

```
GET /api/v1/ws
Upgrade: websocket
Connection: Upgrade
Authorization: Bearer <access_token>
Origin: https://your-ironmesh-instance.com
```

**Authentication:** The WebSocket route is behind the same JWT middleware as other protected endpoints. Unauthenticated connections are rejected before the upgrade.

**Origin check:** The server verifies the `Origin` header against the `ALLOWED_ORIGINS` whitelist (comma-separated env var).

### Server Events

| Type | Payload | Description |
|------|---------|-------------|
| `scan_complete` | `{ "scan_id": "uuid", "device_id": "uuid", "status": "completed" }` | A device scan finished |
| `vulnerability_found` | `{ "vuln_id": "uuid", "device_id": "uuid", "severity": "critical", "cve_id": "..." }` | New vulnerability discovered |
| `alert_triggered` | `{ "alert_id": "uuid", "severity": "high", "alert_type": "telnet_exposed" }` | New alert created |
| `device_discovered` | `{ "device_id": "uuid", "ip_address": "..." }` | New device found on network |
| `ping` | `{}` | Keepalive (every 30s) |

### Client Events

| Type | Payload | Description |
|------|---------|-------------|
| `pong` | `{}` | Respond to keepalive ping |

### Connection Lifecycle

1. Client connects with valid JWT in `Authorization` header
2. Server verifies JWT + Origin + upgrades to WebSocket
3. Server sends `ping` every 30 seconds
4. Client must respond with `pong` within 60 seconds
5. Connection drops: client should auto-reconnect with exponential backoff
6. Server broadcasts events to all connected clients
