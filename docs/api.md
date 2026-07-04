# IronMesh API Documentation

Base URL: `/api/v1`

## Authentication

All protected endpoints require a Bearer token in the `Authorization` header.  
Tokens are obtained via `POST /auth/login`.

### Token Types

| Token | TTL | Storage | Usage |
|-------|-----|---------|-------|
| Access Token | 15 min | Client memory | `Authorization: Bearer <token>` |
| Refresh Token | 7 days | Secure storage | `POST /auth/refresh` |

### Token Rotation
- Refresh tokens are rotated on each use (old token invalidated)
- Password change invalidates ALL refresh tokens for the user
- Logout blacklists the current access token (15 min residual)

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

#### `GET /auth/me` (Protected)
Returns current user info.

#### `GET /auth/permissions` (Protected)
Returns the role, permission list, and hierarchy level for the current user.

---

### RBAC Permissions

| Role | Level | Description |
|------|-------|-------------|
| `viewer` | 0 | Read-only access to devices, scans, vulnerabilities, alerts, firmware |
| `auditor` | 1 | Same as viewer + audit log access |
| `operator` | 2 | Full CRUD on devices, scans, vulnerabilities, alerts, firmware, safelists, webhooks |
| `admin` | 3 | All permissions including user management and admin functions |

Permissions follow the pattern `<resource>:<action>`. Admins get `<resource>:*` wildcards.

---

### Devices

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/devices` | Authenticated | List all devices |
| GET | `/devices/:id` | Authenticated | Get device details |
| DELETE | `/devices/:id` | Admin | Delete a device |
| POST | `/devices/:id/scan` | Admin | Trigger scan on device |
| GET | `/devices/:id/risk-breakdown` | Authenticated | Get risk score breakdown |

---

### Scans

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/scans` | Authenticated | List all scans |
| GET | `/scans/:id` | Authenticated | Get scan details |
| POST | `/scan/network` | Admin | Trigger network-wide scan |

---

### Vulnerabilities

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/vulnerabilities` | Authenticated | List vulnerabilities |
| PATCH | `/vulnerabilities/:id/resolve` | Admin | Mark vulnerability as resolved |

---

### Firmware

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/firmware` | Authenticated | List firmware entries |
| POST | `/firmware/:id/analyze` | Admin | Trigger firmware analysis |
| POST | `/firmware/upload` | Admin | Upload firmware file |

**Upload constraints:**
- Max file size: 256 MB
- Valid extensions: `.bin`, `.elf`, `.gz`, `.tar`, `.bz2`, `.xz`, `.zip`, `.rar`, `.7z`, `.img`, `.fw`, `.rom`, `.squashfs`, `.ubifs`, `.jffs2`, `.cramfs`
- Magic byte verification performed on upload

---

### Alerts

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/alerts` | Authenticated | List alerts |
| POST | `/alerts/:id/ack` | Authenticated | Acknowledge an alert |

---

### Webhooks

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/webhooks` | Admin | List webhooks |
| POST | `/webhooks` | Admin | Create webhook |
| DELETE | `/webhooks/:id` | Admin | Delete webhook |
| POST | `/webhooks/:id/test` | Admin | Test webhook delivery |

---

### Users

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/users` | Admin | List all users |
| POST | `/users` | Admin | Create new user |

---

### Audit Log

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/audit-log` | Auditor+ | List audit log entries |

---

### Other

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | Public | Health check |
| GET | `/stats` | Authenticated | Dashboard statistics |
| GET | `/kev/status` | Authenticated | KEV catalog status |
| GET | `/safelists` | Authenticated | List safelist entries |
| POST | `/safelists` | Admin | Create safelist entry |
| DELETE | `/safelists/:id` | Admin | Delete safelist entry |
| GET | `/scan-profiles` | Authenticated | List scan profiles |
| GET | `/scan-scopes` | Authenticated | List scan scopes |
| POST | `/scan-scopes` | Admin | Create scan scope |
| DELETE | `/scan-scopes/:id` | Admin | Delete scan scope |
| GET | `/ws` | Authenticated | WebSocket connection |

---

## WebSocket

Connect to `wss://<host>/api/v1/ws` with the same Bearer token.

### Server Events

| Type | Description |
|------|-------------|
| `scan_complete` | A device scan finished |
| `vulnerability_found` | New vulnerability discovered |
| `alert_triggered` | New alert created |
| `device_discovered` | New device found on network |
| `ping` | Keepalive (every 30s) |

### Client Events

| Type | Description |
|------|-------------|
| `pong` | Respond to keepalive ping |

---

## Error Responses

All endpoints return a uniform response envelope:

```json
{
  "data": <payload> | null,
  "error": <string> | null
}
```

### HTTP Status Codes

| Code | Meaning |
|------|---------|
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

---

## Rate Limiting

Rate limit headers are returned on every response:

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Max requests per window |
| `X-RateLimit-Remaining` | Requests remaining in current window |
| `X-RateLimit-Reset` | Unix timestamp when window resets |

Default: 60 requests per minute per IP. Per-endpoint rules may apply.
