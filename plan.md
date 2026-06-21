# IronMesh — IoT Security Platform
### Full Project Specification & Agent Build Orders

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [The Problem We Solve](#2-the-problem-we-solve)
3. [Architecture Overview](#3-architecture-overview)
4. [Tech Stack](#4-tech-stack)
5. [Directory Structure](#5-directory-structure)
6. [Database Schema](#6-database-schema)
7. [Backend — Go API](#7-backend--go-api)
8. [Scanner Engine](#8-scanner-engine)
9. [Firmware Analysis Pipeline](#9-firmware-analysis-pipeline)
10. [Risk Scoring Engine](#10-risk-scoring-engine)
11. [Alerting System](#11-alerting-system)
12. [Frontend — React Dashboard](#12-frontend--react-dashboard)
13. [Docker & Deployment](#13-docker--deployment)
14. [Agent Build Orders](#14-agent-build-orders)
15. [Testing & Demo Strategy](#15-testing--demo-strategy)

---

## 1. Project Overview

**IronMesh** is an open-source IoT security platform that gives security teams full visibility into every connected device on their network — what it is, what vulnerabilities it carries, what firmware it runs, how risky it is, and when it does something suspicious.

It is built to be deployed in minutes on real hardware, tested against real CVEs, and extended by the community. It is not a dashboard with fake data. It is a working security tool.

**Target users:**
- Security engineers at companies with IoT-heavy infrastructure (hospitals, manufacturers, smart buildings)
- Small security teams with no dedicated IoT visibility tooling
- Individuals running homelabs who want to audit their own devices
- Researchers demonstrating IoT attack surfaces

**What makes it different from commercial tools (Armis, Claroty, Nozomi):**
- Fully open source, self-hosted, no vendor lock-in
- One-command Docker deployment
- Designed to run on a single Raspberry Pi for homelab use, or scale to enterprise
- Every scan result maps to a real CVE with remediation steps

---

## 2. The Problem We Solve

These are real threats from 2025–2026, not hypothetical scenarios.

### Threat 1 — Botnet Recruitment (Critical)
Botnets like Aisuru/TurboMirai now achieve 20+ Tbps DDoS capability by compromising home routers, IP cameras, and smart TVs. The root cause is always the same: default credentials and exposed management ports (Telnet/SSH). IronMesh detects this by scanning for open Telnet (port 23), testing default credentials, and monitoring for abnormal outbound traffic patterns indicative of C2 communication.

### Threat 2 — IP Camera Exploitation (Critical)
Nation-state actors (Iran-linked groups, Feb 2026) targeted AVTECH cameras across hospitals and financial institutions. AVTECH cameras carry CVE-2024-7029, allowing unauthenticated remote code execution. IronMesh cross-references every discovered camera's make/model against the CISA Known Exploited Vulnerabilities (KEV) list and flags unauthenticated RTSP stream exposure.

### Threat 3 — Supply Chain Firmware Malware (High)
BadBox 2.0 pre-infected 10M+ Android TV boxes and routers before they reached customers by injecting malware during manufacturing. Devices arrive already compromised — no user action required. IronMesh detects this through firmware entropy analysis (packed/encrypted malicious payloads have abnormally high entropy) and by flagging Android Debug Bridge (ADB) port 5555 exposure.

### Threat 4 — OT/ICS Infrastructure Attacks (Critical)
In April 2026, CISA issued emergency advisories for Honeywell, Mitsubishi Electric, and Delta Electronics. Industrial PLCs using Modbus and DNP3 protocols carry no authentication by design. IronMesh fingerprints industrial protocols on the network and treats any internet-reachable OT device as an automatic critical risk.

### Threat 5 — Insecure Communication (High)
24% of IoT companion apps have TLS issues. Unencrypted MQTT brokers (port 1883) are trivially intercepted. IronMesh scans for cleartext protocol usage, detects TLS versions below 1.2, and flags HTTP management interfaces.

### Threat 6 — Default & Weak Credentials (High)
820,000 IoT attacks happen daily, most via default credentials. Mirai's entire power came from scanning for admin/admin and root/root. IronMesh tests every discovered device against the top-100 default credential list and immediately scores any match as Critical (9.0+).

---

## 3. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      React Frontend                         │
│         Dashboard · Inventory · Alerts · Reports           │
└────────────────────────┬────────────────────────────────────┘
                         │ REST API (HTTP/JSON)
┌────────────────────────▼────────────────────────────────────┐
│                    Go API Server                            │
│    /devices  /scans  /vulns  /firmware  /alerts  /risks    │
└──────┬──────────────┬───────────────┬────────────┬──────────┘
       │              │               │            │
┌──────▼──────┐ ┌─────▼──────┐ ┌─────▼────┐ ┌────▼────────┐
│   Scanner   │ │  Firmware  │ │  Risk    │ │  Alerting   │
│   Engine    │ │  Analyzer  │ │  Scorer  │ │  Engine     │
│ (nmap+Go)   │ │  (Python)  │ │  (Go)    │ │  (Go)       │
└──────┬──────┘ └─────┬──────┘ └─────┬────┘ └────┬────────┘
       │              │               │            │
┌──────▼──────────────▼───────────────▼────────────▼──────────┐
│                     PostgreSQL                              │
│   devices · scans · vulnerabilities · firmware · alerts    │
└─────────────────────────────────────────────────────────────┘
```

**Data flow:**
1. Scanner Engine discovers devices on the network via nmap, identifies them by banner/fingerprint
2. For each device, the Vulnerability Scanner checks open ports, protocols, credentials, and TLS versions
3. Discovered firmware versions are sent to the Firmware Analyzer for entropy analysis and CVE lookup
4. The Risk Scorer aggregates all findings and produces a 0–10 risk score per device
5. The Alerting Engine monitors for threshold breaches and behavioral anomalies in real time
6. All data is persisted in PostgreSQL and served by the Go API to the React frontend

---

## 4. Tech Stack

| Layer | Technology | Reason |
|---|---|---|
| Backend API | Go (Golang) | Fast, statically typed, excellent networking primitives, compiles to a single binary |
| Scanner Engine | Go + nmap | nmap is the industry standard; Go wraps it and processes output |
| Firmware Analyzer | Python 3 | binwalk, entropy tools, and CVE libraries are Python-first |
| Database | PostgreSQL 16 | Relational, ACID, excellent JSON support for flexible vulnerability data |
| Frontend | React + TypeScript | Component-based, strong typing, recharts for data visualization |
| Styling | Tailwind CSS | Utility-first, fast to build, consistent design system |
| Containerization | Docker + Docker Compose | One-command deployment, reproducible environments |
| CVE Data | NVD API (NIST) | Free, authoritative, updated daily |
| CISA KEV | CISA KEV JSON feed | Known Exploited Vulnerabilities — the highest-priority CVE subset |
| Default Creds DB | RouterSploit / SecLists | Community-maintained default credential lists |

---

## 5. Directory Structure

```
ironmesh/
├── README.md
├── THREAT_MODEL.md
├── docker-compose.yml
├── .env.example
│
├── backend/
│   ├── main.go
│   ├── go.mod
│   ├── go.sum
│   ├── config/
│   │   └── config.go
│   ├── api/
│   │   ├── router.go
│   │   ├── devices.go
│   │   ├── scans.go
│   │   ├── vulnerabilities.go
│   │   ├── firmware.go
│   │   ├── alerts.go
│   │   └── risks.go
│   ├── db/
│   │   ├── db.go
│   │   └── migrations/
│   │       ├── 001_create_devices.sql
│   │       ├── 002_create_scans.sql
│   │       ├── 003_create_vulnerabilities.sql
│   │       ├── 004_create_firmware.sql
│   │       └── 005_create_alerts.sql
│   ├── scanner/
│   │   ├── nmap.go
│   │   ├── ports.go
│   │   ├── credentials.go
│   │   ├── protocols.go
│   │   └── tls.go
│   ├── risk/
│   │   └── scorer.go
│   ├── alerts/
│   │   └── engine.go
│   └── models/
│       ├── device.go
│       ├── scan.go
│       ├── vulnerability.go
│       ├── firmware.go
│       └── alert.go
│
├── firmware-analyzer/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py
│   ├── entropy.py
│   ├── cve_lookup.py
│   └── binwalk_runner.py
│
├── frontend/
│   ├── package.json
│   ├── tsconfig.json
│   ├── tailwind.config.js
│   ├── src/
│   │   ├── main.tsx
│   │   ├── App.tsx
│   │   ├── api/
│   │   │   └── client.ts
│   │   ├── components/
│   │   │   ├── DeviceInventory.tsx
│   │   │   ├── VulnScanner.tsx
│   │   │   ├── FirmwarePanel.tsx
│   │   │   ├── RiskScore.tsx
│   │   │   ├── AlertFeed.tsx
│   │   │   └── NetworkMap.tsx
│   │   └── pages/
│   │       ├── Dashboard.tsx
│   │       ├── Devices.tsx
│   │       ├── Vulnerabilities.tsx
│   │       └── Firmware.tsx
│
└── data/
    ├── default-credentials.txt
    ├── cisa-kev.json          # auto-updated
    └── nvd-cache/             # local NVD cache
```

---

## 6. Database Schema

### devices
```sql
CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address INET NOT NULL,
    mac_address MACADDR,
    hostname TEXT,
    vendor TEXT,
    device_type TEXT,          -- 'router', 'camera', 'sensor', 'plc', 'unknown'
    os_fingerprint TEXT,
    firmware_version TEXT,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    risk_score NUMERIC(3,1) DEFAULT 0.0,
    is_active BOOLEAN DEFAULT TRUE,
    tags TEXT[],
    raw_nmap JSONB,
    UNIQUE(ip_address)
);
```

### scans
```sql
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'running',  -- 'running', 'complete', 'failed'
    scan_type TEXT NOT NULL,                 -- 'full', 'quick', 'credential', 'firmware'
    open_ports JSONB,
    services JSONB,
    scan_output TEXT
);
```

### vulnerabilities
```sql
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    cve_id TEXT,
    cvss_score NUMERIC(3,1),
    severity TEXT NOT NULL,   -- 'critical', 'high', 'medium', 'low', 'info'
    title TEXT NOT NULL,
    description TEXT,
    affected_component TEXT,
    remediation TEXT,
    is_kev BOOLEAN DEFAULT FALSE,   -- is it on CISA KEV list?
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    is_resolved BOOLEAN DEFAULT FALSE
);
```

### firmware
```sql
CREATE TABLE firmware (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    version TEXT,
    vendor TEXT,
    checksum TEXT,
    file_path TEXT,
    analyzed_at TIMESTAMPTZ,
    entropy_score NUMERIC(5,4),    -- 0.0 - 8.0, >7.2 = suspicious
    has_default_creds BOOLEAN,
    has_telnet BOOLEAN,
    has_backdoor_indicators BOOLEAN,
    strings_of_interest TEXT[],    -- suspicious strings found in binary
    cve_matches TEXT[],            -- CVEs matched to this firmware version
    analysis_status TEXT DEFAULT 'pending',
    analysis_report JSONB
);
```

### alerts
```sql
CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    severity TEXT NOT NULL,   -- 'critical', 'high', 'medium', 'low'
    alert_type TEXT NOT NULL, -- 'brute_force', 'port_scan', 'default_creds', 'anomalous_traffic', 'new_device', 'offline'
    title TEXT NOT NULL,
    description TEXT,
    triggered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at TIMESTAMPTZ,
    is_acknowledged BOOLEAN DEFAULT FALSE,
    metadata JSONB
);
```

---

## 7. Backend — Go API

### Entry Point (`main.go`)

```go
package main

import (
    "log"
    "github.com/yourusername/ironmesh/config"
    "github.com/yourusername/ironmesh/api"
    "github.com/yourusername/ironmesh/db"
)

func main() {
    cfg := config.Load()
    database := db.Connect(cfg.DatabaseURL)
    defer database.Close()
    db.RunMigrations(database)
    router := api.NewRouter(database, cfg)
    log.Printf("IronMesh API running on :%s", cfg.Port)
    log.Fatal(router.Run(":" + cfg.Port))
}
```

### API Routes (`api/router.go`)

```go
// GET  /api/v1/devices              — list all devices with risk scores
// GET  /api/v1/devices/:id          — single device detail
// POST /api/v1/devices/:id/scan     — trigger a scan on a device
// GET  /api/v1/devices/:id/vulns    — vulnerabilities for a device
// GET  /api/v1/scans                — all scan history
// GET  /api/v1/scans/:id            — single scan result
// GET  /api/v1/vulnerabilities      — all vulns, filterable by severity/device
// GET  /api/v1/firmware             — all firmware records
// POST /api/v1/firmware/:id/analyze — trigger firmware analysis
// GET  /api/v1/alerts               — alert feed, filterable
// POST /api/v1/alerts/:id/ack       — acknowledge an alert
// GET  /api/v1/stats                — dashboard summary stats
// POST /api/v1/scan/network         — trigger full network discovery scan
```

### Key API Handler — Device Scan (`api/scans.go`)

The scan handler does the following in order:
1. Validates the device exists in the database
2. Creates a scan record with status "running"
3. Launches the scan asynchronously in a goroutine
4. Returns the scan ID immediately to the client (non-blocking)
5. The goroutine runs the full scan pipeline:
   - Port scan (nmap)
   - Service fingerprinting
   - Default credential testing
   - Protocol detection (Modbus, MQTT, RTSP, Telnet)
   - TLS version check
   - CISA KEV cross-reference
6. Updates the scan record and device risk score on completion
7. Creates alerts for any critical findings

### Stats Endpoint (`api/risks.go`)

Returns the dashboard summary:
```json
{
  "total_devices": 142,
  "active_devices": 139,
  "critical_vulns": 3,
  "high_vulns": 8,
  "medium_vulns": 14,
  "unresolved_alerts": 6,
  "firmware_outdated": 18,
  "avg_risk_score": 6.2,
  "kev_affected_devices": 4
}
```

---

## 8. Scanner Engine

The scanner is the heart of IronMesh. It has five components:

### 8.1 Network Discovery (`scanner/nmap.go`)

Uses nmap under the hood via Go's `os/exec`. Runs in two phases:

**Phase 1 — Host discovery (fast):**
```
nmap -sn 192.168.1.0/24 -oX -
```
Discovers all live hosts in the subnet without port scanning. Parses the XML output to extract IPs and MACs.

**Phase 2 — Deep scan (per device):**
```
nmap -sV -sC -O --script=banner,http-title,rtsp-url-brute -p 22,23,80,443,554,1883,1884,5555,8883,47808,502 -oX - <IP>
```
Key ports scanned:
- 22: SSH
- 23: Telnet (immediate red flag)
- 80/443: HTTP/HTTPS management interface
- 554: RTSP (cameras)
- 1883/8883: MQTT (plaintext vs TLS)
- 5555: ADB (Android Debug Bridge — BadBox indicator)
- 47808: BACnet (building automation — OT protocol)
- 502: Modbus (industrial control — OT protocol)

### 8.2 Default Credential Testing (`scanner/credentials.go`)

Loads a credential list from `data/default-credentials.txt` (sourced from SecLists). For each device, based on detected services:

- If SSH is open → try top-50 SSH default creds via `golang.org/x/crypto/ssh`
- If HTTP is open → try top-50 HTTP basic auth and form-based login defaults
- If Telnet is open → try top-20 Telnet default creds

**Safety rules:**
- Maximum 3 attempts per credential pair before moving to next
- 500ms delay between attempts to avoid lockouts
- Never test more than 50 credential pairs per device per scan
- Log every attempt for audit trail
- Immediately stop if lockout response detected (429 or account-locked messages)

### 8.3 Protocol Detection (`scanner/protocols.go`)

Identifies dangerous protocols on the network:

| Protocol | Port | Risk if found | Detection method |
|---|---|---|---|
| Telnet | 23 | Critical | Banner grab: contains "login:" |
| Modbus | 502 | Critical | Send function code 0x11, check response |
| BACnet | 47808 | High | UDP probe, check BACnet header |
| RTSP unauth | 554 | High | OPTIONS request without auth header |
| MQTT plaintext | 1883 | High | CONNECT packet, check no TLS |
| ADB | 5555 | Critical | TCP connect, read "CNXN" banner |
| HTTP mgmt | 80 | Medium | HTTP GET, check for device admin panel |

### 8.4 TLS Scanner (`scanner/tls.go`)

For every HTTPS or MQTTS endpoint:
1. Attempt TLS 1.0 handshake → if succeeds, flag as high severity
2. Attempt TLS 1.1 handshake → if succeeds, flag as medium severity
3. Check certificate expiry → flag if expired or expiring within 30 days
4. Check for self-signed certificates → flag as medium severity
5. Check cipher suites for known-weak algorithms (RC4, DES, MD5)

### 8.5 CISA KEV Cross-Reference (`scanner/protocols.go`)

On startup and daily thereafter, IronMesh fetches the CISA KEV feed:
```
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```
Cached locally in `data/cisa-kev.json`. Every vulnerability found during scanning is checked against this list. KEV matches are marked `is_kev = TRUE` and automatically trigger a Critical alert regardless of their CVSS score, because being on the KEV list means they are actively exploited in the wild.

---

## 9. Firmware Analysis Pipeline

The firmware analyzer runs as a separate Python microservice, communicating with the Go backend via HTTP.

### 9.1 Entropy Analysis (`firmware-analyzer/entropy.py`)

Shannon entropy measures the randomness of data. Normal code has entropy around 4.0–6.5. Encrypted or compressed malicious payloads push entropy above 7.2.

```python
import math
from collections import Counter

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum(
        (c / total) * math.log2(c / total)
        for c in counts.values()
        if c > 0
    )

def analyze_firmware(filepath: str) -> dict:
    with open(filepath, 'rb') as f:
        data = f.read()
    entropy = shannon_entropy(data)
    return {
        "entropy_score": round(entropy, 4),
        "suspicious": entropy > 7.2,
        "verdict": "encrypted_or_packed" if entropy > 7.2 else "normal"
    }
```

Entropy thresholds:
- Below 6.5: Normal firmware (readable code, strings, data sections)
- 6.5 – 7.2: Mildly suspicious (compressed sections, normal for some vendors)
- Above 7.2: High suspicion (encrypted payload, packed binary, possible malware)

### 9.2 String Extraction (`firmware-analyzer/binwalk_runner.py`)

Uses `binwalk` to extract embedded files and then `strings` to search for indicators of compromise:

Suspicious strings searched for:
- `/bin/sh`, `/bin/bash` in unexpected locations
- `wget`, `curl`, `chmod +x` (dropper behavior)
- Known C2 domains or IPs (matched against threat intel feeds)
- `telnetd`, `dropbear` (backdoor services)
- Base64-encoded blobs over 100 chars (potential encoded payloads)
- Hard-coded credentials patterns (regex: `password=`, `passwd=`, `secret=`)

### 9.3 CVE Lookup (`firmware-analyzer/cve_lookup.py`)

Given a device vendor and firmware version string:
1. Query NVD API: `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<vendor>+<version>`
2. Parse results, filter by CVSS score >= 4.0
3. Return matched CVEs with CVSS scores, descriptions, and remediation links
4. Cache results locally to avoid hammering the NVD API (rate limited to 5 req/30s without API key)

---

## 10. Risk Scoring Engine

Every device gets a risk score from 0.0 to 10.0. The scoring is additive and capped.

```go
// risk/scorer.go

type RiskFactors struct {
    HasDefaultCreds      bool    // +4.0 (auto-critical)
    HasTelnet            bool    // +3.0
    HasADB               bool    // +3.5 (BadBox indicator)
    HasModbus            bool    // +2.5 (OT protocol)
    HasUnauthRTSP        bool    // +2.0
    HasPlaintextMQTT     bool    // +1.5
    HasHTTPMgmt          bool    // +1.0
    HasWeakTLS           bool    // +1.5
    KnownCVECount        int     // +0.5 per CVE, max +3.0
    KEVMatchCount        int     // +2.0 per KEV match, max +4.0
    FirmwareOutdated     bool    // +1.0
    HighEntropyFirmware  bool    // +2.0
    DaysSinceLastUpdate  int     // +0.1 per 30 days, max +1.0
}

func CalculateRiskScore(factors RiskFactors) float64 {
    score := 0.0
    if factors.HasDefaultCreds  { score += 4.0 }
    if factors.HasTelnet        { score += 3.0 }
    if factors.HasADB           { score += 3.5 }
    if factors.HasModbus        { score += 2.5 }
    if factors.HasUnauthRTSP   { score += 2.0 }
    if factors.HasPlaintextMQTT { score += 1.5 }
    if factors.HasHTTPMgmt      { score += 1.0 }
    if factors.HasWeakTLS       { score += 1.5 }
    cveScore := math.Min(float64(factors.KnownCVECount)*0.5, 3.0)
    score += cveScore
    kevScore := math.Min(float64(factors.KEVMatchCount)*2.0, 4.0)
    score += kevScore
    if factors.FirmwareOutdated    { score += 1.0 }
    if factors.HighEntropyFirmware { score += 2.0 }
    dayScore := math.Min(float64(factors.DaysSinceLastUpdate)/30*0.1, 1.0)
    score += dayScore
    return math.Min(score, 10.0)
}
```

Risk score ranges:
- 0.0 – 2.9: Low (green)
- 3.0 – 5.9: Medium (blue)
- 6.0 – 7.9: High (amber)
- 8.0 – 10.0: Critical (red)

---

## 11. Alerting System

The alerting engine runs as a background goroutine, checking for conditions every 60 seconds and on every scan completion.

### Alert Types

| Alert Type | Trigger Condition | Severity |
|---|---|---|
| `default_creds` | Default credential login succeeds | Critical |
| `kev_match` | Device firmware matches a CISA KEV entry | Critical |
| `brute_force` | 5+ failed login attempts in 60 seconds | Critical |
| `adb_exposed` | ADB port 5555 open and responding | Critical |
| `telnet_open` | Telnet port 23 open | High |
| `new_device` | Unknown device appears on network | High |
| `anomalous_traffic` | Device sends traffic to unexpected destinations | High |
| `plaintext_mqtt` | MQTT without TLS detected | High |
| `unauth_rtsp` | Camera RTSP stream accessible without credentials | High |
| `firmware_entropy` | Firmware entropy above 7.2 | High |
| `tls_weak` | TLS 1.0 or 1.1 in use | Medium |
| `device_offline` | Device not seen for 30+ minutes | Medium |
| `cert_expiring` | TLS certificate expiring within 30 days | Medium |

### Alert Deduplication

The same alert type for the same device is not re-raised within a 24-hour window unless the condition worsens. This prevents alert fatigue.

---

## 12. Frontend — React Dashboard

### Pages

**Dashboard (home):**
- 4 metric cards: total devices, open vulnerabilities, unacknowledged alerts, average risk score
- Risk distribution bar chart (recharts)
- Recent alerts feed (last 10, with severity color coding)
- Firmware status summary

**Devices page:**
- Searchable, filterable table of all devices
- Filter by: risk score range, device type, last seen, vulnerability count
- Click any device → device detail page with full scan history, vulnerability list, and firmware status
- "Scan now" button triggers an on-demand scan

**Vulnerabilities page:**
- Full vulnerability list across all devices
- Filter by: CVE ID, severity, device, KEV status, resolved/unresolved
- Each row shows: CVE, CVSS score, affected device, discovered date, remediation link
- CISA KEV badges shown prominently in red

**Firmware page:**
- Firmware records with entropy scores visualized as a meter
- High-entropy firmware highlighted in amber/red
- Link to full analysis report per firmware record

### Key Components

**`RiskScore.tsx`** — Circular progress ring showing 0–10 score with color-coded severity. Animates on mount.

**`AlertFeed.tsx`** — Real-time feed using polling every 30 seconds. New alerts animate in from the top. Acknowledge button marks as resolved.

**`NetworkMap.tsx`** — Grid of device nodes color-coded by risk score. Flagged devices pulse with a red border. Click any node to jump to device detail.

**`VulnScanner.tsx`** — Shows active scan progress, lists findings as they come in (polling scan status endpoint every 2 seconds while scan is running).

---

## 13. Docker & Deployment

### `docker-compose.yml`

```yaml
version: '3.9'

services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: ironmesh
      POSTGRES_USER: ironmesh
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ironmesh"]
      interval: 5s
      timeout: 5s
      retries: 5

  backend:
    build: ./backend
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      DATABASE_URL: postgres://ironmesh:${DB_PASSWORD}@postgres:5432/ironmesh
      PORT: 8080
      NETWORK_CIDR: ${NETWORK_CIDR:-192.168.1.0/24}
      NVD_API_KEY: ${NVD_API_KEY:-}
    ports:
      - "8080:8080"
    network_mode: host  # required for nmap to see the local network
    cap_add:
      - NET_ADMIN
      - NET_RAW

  firmware-analyzer:
    build: ./firmware-analyzer
    depends_on:
      - postgres
    environment:
      DATABASE_URL: postgres://ironmesh:${DB_PASSWORD}@postgres:5432/ironmesh
      API_URL: http://backend:8080
    volumes:
      - firmware_data:/firmware

  frontend:
    build: ./frontend
    depends_on:
      - backend
    ports:
      - "3000:80"
    environment:
      REACT_APP_API_URL: http://localhost:8080

volumes:
  postgres_data:
  firmware_data:
```

### Deployment Steps

```bash
# 1. Clone the repo
git clone https://github.com/yourusername/ironmesh
cd ironmesh

# 2. Copy and configure environment
cp .env.example .env
# Edit .env: set DB_PASSWORD, NETWORK_CIDR, optionally NVD_API_KEY

# 3. Start everything
docker compose up -d

# 4. Access the dashboard
open http://localhost:3000

# 5. Trigger your first network scan
curl -X POST http://localhost:8080/api/v1/scan/network
```

That is the complete deployment. One command, everything starts.

---

## 14. Agent Build Orders

These are precise, sequenced instructions for AI coding agents (Claude Code, Cursor, Copilot, etc.) to build each component. Execute them in order. Each order is self-contained and testable.

---

### ORDER 001 — Project Scaffolding

**Task:** Create the full project directory structure and initialize all dependency files.

**Instructions:**
1. Create the directory tree exactly as specified in Section 5
2. Initialize Go module: `go mod init github.com/yourusername/ironmesh`
3. Add Go dependencies:
   - `github.com/gin-gonic/gin` (HTTP router)
   - `github.com/lib/pq` (PostgreSQL driver)
   - `github.com/google/uuid` (UUID generation)
   - `golang.org/x/crypto` (SSH credential testing)
   - `github.com/joho/godotenv` (env file loading)
4. Create React app with TypeScript: `npx create-react-app frontend --template typescript`
5. Add frontend dependencies: `recharts`, `@types/recharts`, `axios`, `tailwindcss`
6. Create `.env.example` with all required variables
7. Create `README.md` with project description, setup steps, and screenshot placeholder

**Done when:** `go build ./...` and `npm install` both complete without errors.

---

### ORDER 002 — Database & Migrations

**Task:** Set up PostgreSQL schema with all tables and indexes.

**Instructions:**
1. Create `backend/db/db.go` — connection pool using `database/sql` with `lib/pq`
2. Implement `RunMigrations()` that executes all `.sql` files in `db/migrations/` in numeric order
3. Create all 5 migration files with the exact SQL from Section 6
4. Add indexes:
   - `devices(ip_address)` — unique index (already in schema)
   - `vulnerabilities(device_id, severity)` — for dashboard queries
   - `vulnerabilities(is_kev)` — for KEV filter
   - `alerts(device_id, triggered_at)` — for alert feed
   - `scans(device_id, started_at)` — for scan history
5. Create `backend/models/` files with Go structs matching each table, using proper JSON tags

**Done when:** Running `docker compose up postgres` and then `go run main.go` successfully connects and runs all migrations.

---

### ORDER 003 — Go API Server (CRUD)

**Task:** Build all REST API endpoints with full CRUD operations.

**Instructions:**
1. Create `api/router.go` — Gin router with all routes from Section 7, CORS middleware enabled
2. Implement `api/devices.go`:
   - `GET /devices` — list with pagination (page, limit query params), filter by risk_score_min/max, device_type
   - `GET /devices/:id` — single device with latest scan and open vulnerabilities
   - `DELETE /devices/:id` — soft delete (set is_active = false)
3. Implement `api/vulnerabilities.go`:
   - `GET /vulnerabilities` — list with filters: severity, device_id, is_kev, is_resolved
   - `PATCH /vulnerabilities/:id/resolve` — mark as resolved
4. Implement `api/alerts.go`:
   - `GET /alerts` — list with filters: severity, is_acknowledged, device_id
   - `POST /alerts/:id/ack` — acknowledge alert (sets acknowledged_at = NOW())
5. Implement `api/risks.go`:
   - `GET /stats` — aggregate stats query (all counts from dashboard)
6. All handlers return consistent JSON: `{"data": ..., "error": null}` or `{"data": null, "error": "message"}`

**Done when:** All endpoints return correct responses when tested with `curl`.

---

### ORDER 004 — Network Discovery Scanner

**Task:** Build the nmap-based network discovery and deep device scanner.

**Instructions:**
1. Create `scanner/nmap.go`:
   - `DiscoverHosts(cidr string) ([]string, error)` — runs `nmap -sn <cidr> -oX -`, parses XML, returns live IPs
   - `DeepScan(ip string) (*ScanResult, error)` — runs full nmap scan with service detection on the ports listed in Section 8.1, parses XML result
   - Handle nmap not found: return clear error telling user to install nmap
2. Create `scanner/protocols.go`:
   - `DetectProtocols(ip string, openPorts []int) []ProtocolFinding`
   - Implement Telnet detection (banner grab port 23)
   - Implement ADB detection (TCP connect port 5555, read banner)
   - Implement MQTT detection (attempt CONNECT packet on port 1883)
   - Implement Modbus detection (send function code 0x11 to port 502)
   - Implement RTSP detection (OPTIONS request to port 554)
3. Create `scanner/tls.go`:
   - `CheckTLS(host string, port int) TLSResult`
   - Test TLS 1.0, 1.1, 1.2 support
   - Check certificate validity and expiry
4. Implement the full scan pipeline in `api/scans.go`:
   - `POST /scans/network` — triggers host discovery, creates/updates device records
   - `POST /devices/:id/scan` — triggers deep scan on one device, runs all checks, saves results

**Done when:** Running a network scan against a local subnet discovers devices and saves them to the database.

---

### ORDER 005 — Default Credential Scanner

**Task:** Build the safe default credential testing module.

**Instructions:**
1. Create `data/default-credentials.txt` — populate with top 100 entries from SecLists IoT default credentials (format: `username:password` one per line)
2. Create `scanner/credentials.go`:
   - `TestSSHCreds(ip string, port int, creds []Credential) CredentialResult` — uses `golang.org/x/crypto/ssh`, implements the safety rules: max 3 attempts per pair, 500ms delay, stop on lockout detection
   - `TestHTTPCreds(ip string, port int, creds []Credential) CredentialResult` — tests HTTP Basic Auth via `net/http`, follows same safety rules
   - `TestTelnetCreds(ip string, port int, creds []Credential) CredentialResult` — raw TCP connection, reads banner, sends username/password
   - `LoadCredentials(filepath string) ([]Credential, error)` — loads and parses the credentials file
3. When default credentials are found:
   - Create a `vulnerability` record: severity = "critical", cvss_score = 9.5, title = "Default credentials active", cve_id = null
   - Create an `alert` record: alert_type = "default_creds", severity = "critical"
   - Add `has_default_creds = true` to risk factor calculation

**Done when:** Scanner correctly identifies a test device with default credentials and creates the appropriate vulnerability and alert records.

---

### ORDER 006 — CISA KEV Integration

**Task:** Build the CISA Known Exploited Vulnerabilities feed integration.

**Instructions:**
1. Create `backend/kev/updater.go`:
   - `FetchKEV() error` — downloads from `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`, saves to `data/cisa-kev.json`
   - `LoadKEV() ([]KEVEntry, error)` — parses and returns the local cache
   - `IsKEV(cveID string) bool` — checks if a CVE ID is in the KEV list
2. Run `FetchKEV()` on startup and schedule daily refresh using a background goroutine with a 24-hour ticker
3. In the vulnerability scanning pipeline, after finding any CVE:
   - Call `IsKEV(cveID)` 
   - If true: set `is_kev = true` on the vulnerability record
   - If true: set severity to "critical" regardless of CVSS score
   - If true: create an alert with type "kev_match"
4. Add `GET /api/v1/kev/status` endpoint that returns: last_updated timestamp, total_entries count

**Done when:** KEV list downloads on startup, is queryable, and KEV matches are flagged correctly in vulnerability records.

---

### ORDER 007 — Risk Scoring Engine

**Task:** Implement the risk scoring system from Section 10.

**Instructions:**
1. Create `risk/scorer.go` with the `RiskFactors` struct and `CalculateRiskScore()` function exactly as specified in Section 10
2. Create `risk/updater.go`:
   - `UpdateDeviceRiskScore(db *sql.DB, deviceID string) error`
   - Queries all open vulnerabilities for the device
   - Queries all firmware records for the device
   - Builds a `RiskFactors` struct from the data
   - Calls `CalculateRiskScore()` 
   - Updates `devices.risk_score` in the database
3. Call `UpdateDeviceRiskScore()` after every scan completion
4. Add `GET /api/v1/devices/:id/risk-breakdown` endpoint that returns the individual factor scores (so users can see exactly why a device scored 8.5, not just the number)

**Done when:** Device risk scores update automatically after scans and the breakdown endpoint returns accurate factor-level data.

---

### ORDER 008 — Alerting Engine

**Task:** Build the alerting system with deduplication.

**Instructions:**
1. Create `alerts/engine.go`:
   - `CreateAlert(db *sql.DB, deviceID string, alertType string, severity string, title string, description string, metadata map[string]interface{}) error`
   - Before creating: check if an unacknowledged alert of the same type exists for the same device within the last 24 hours — if yes, skip (deduplication)
   - After creating: log to stdout with timestamp and severity
2. Implement a `StartAlertMonitor(db *sql.DB)` background goroutine that runs every 60 seconds:
   - Check all devices: if `last_seen` is more than 30 minutes ago and device `is_active`, raise "device_offline" alert
   - Check all firmware: if `analyzed_at` is more than 90 days ago, raise a firmware review alert
3. Integrate alert creation into every component:
   - Scanner raises alerts for: telnet_open, adb_exposed, unauth_rtsp, plaintext_mqtt
   - Credential scanner raises: default_creds
   - KEV integration raises: kev_match
   - Network discovery raises: new_device (for devices not previously seen)
4. `POST /api/v1/alerts/:id/ack` sets `acknowledged_at = NOW()` and `is_acknowledged = true`

**Done when:** Alerts are created correctly by all systems, deduplicated within 24 hours, and acknowledgeable via the API.

---

### ORDER 009 — Firmware Analyzer (Python Microservice)

**Task:** Build the Python firmware analysis service.

**Instructions:**
1. Create `firmware-analyzer/requirements.txt`:
   ```
   fastapi==0.111.0
   uvicorn==0.29.0
   binwalk==2.3.4
   requests==2.31.0
   psycopg2-binary==2.9.9
   ```
2. Create `firmware-analyzer/entropy.py` with `shannon_entropy()` and `analyze_firmware()` exactly as in Section 9.1
3. Create `firmware-analyzer/cve_lookup.py`:
   - `lookup_cve(vendor: str, version: str, nvd_api_key: str = None) -> list`
   - Queries NVD API with rate limit handling (sleep 6 seconds between requests if no API key, 0.6 seconds with key)
   - Returns list of `{"cve_id": str, "cvss": float, "description": str, "url": str}`
4. Create `firmware-analyzer/binwalk_runner.py`:
   - `extract_strings(filepath: str) -> list[str]`
   - Runs binwalk extraction, then `strings` on extracted files
   - Returns strings matching the suspicious patterns from Section 9.2
5. Create `firmware-analyzer/main.py` — FastAPI server:
   - `POST /analyze` — accepts `{"firmware_id": str, "filepath": str, "vendor": str, "version": str}`
   - Runs entropy, string extraction, CVE lookup in sequence
   - Updates the `firmware` table directly via PostgreSQL
   - Returns full analysis report as JSON
6. Create `firmware-analyzer/Dockerfile`:
   - Base: `python:3.12-slim`
   - Install `binwalk` and `nmap` via apt
   - Install Python dependencies
   - Run with uvicorn on port 8001

**Done when:** `POST /analyze` with a firmware file path returns a complete analysis report including entropy score, suspicious strings, and CVE matches.

---

### ORDER 010 — React Frontend

**Task:** Build the complete React dashboard.

**Instructions:**
1. Create `frontend/src/api/client.ts` — axios instance pointing to `REACT_APP_API_URL`, with request/response interceptors for error handling
2. Build `Dashboard.tsx` page:
   - Fetches from `GET /stats` on mount
   - Renders 4 metric cards: devices, vulns, alerts, avg risk score
   - Renders `AlertFeed` component showing last 10 alerts
   - Auto-refreshes every 30 seconds
3. Build `Devices.tsx` page:
   - Searchable table with columns: IP, hostname, vendor, device type, risk score (colored badge), last seen, actions
   - Risk score column: 0–2.9 = green badge, 3–5.9 = blue, 6–7.9 = amber, 8–10 = red
   - "Scan" button on each row calls `POST /devices/:id/scan` and shows loading state
   - Click row to navigate to device detail (use React Router)
4. Build `DeviceDetail.tsx` page:
   - Shows device metadata at top
   - Risk score ring (circular SVG progress indicator, color matches severity)
   - Tabs: Vulnerabilities | Scan History | Firmware
   - Vulnerability tab: list of CVEs with CVSS scores, KEV badge if applicable, resolve button
5. Build `AlertFeed.tsx` component:
   - Severity icon (colored) + title + device name + relative time ("3 min ago")
   - Acknowledge button calls `POST /alerts/:id/ack`
   - New alerts animate in from top
6. Build `Vulnerabilities.tsx` page:
   - Full vulnerability table across all devices
   - Filter bar: severity dropdown, KEV only toggle, resolved toggle
   - KEV matches shown with red "KEV" badge
7. Configure Tailwind CSS with a dark mode toggle (stores preference in localStorage)
8. Create `frontend/Dockerfile`: Node build stage → nginx serve stage

**Done when:** All pages render correctly with real data from the API, scanning works from the UI, and alerts can be acknowledged.

---

### ORDER 011 — Docker Compose & Environment

**Task:** Wire everything together with Docker Compose.

**Instructions:**
1. Create `docker-compose.yml` exactly as specified in Section 13
2. Create `.env.example`:
   ```
   DB_PASSWORD=changeme_strong_password_here
   NETWORK_CIDR=192.168.1.0/24
   NVD_API_KEY=
   ```
3. Create `backend/Dockerfile`:
   - Build stage: `golang:1.22-alpine` — runs `go build -o ironmesh`
   - Install `nmap` in the build stage
   - Run stage: `alpine:latest` — copies binary and nmap, runs `./ironmesh`
4. Verify `network_mode: host` is set on the backend service (required for nmap to scan the local network)
5. Verify `cap_add: [NET_ADMIN, NET_RAW]` is set (required for nmap raw socket access)
6. Test full startup: `docker compose up -d` should start all 4 services in order with health checks passing

**Done when:** `docker compose up -d` starts cleanly, all services are healthy, and `curl http://localhost:8080/api/v1/stats` returns a valid JSON response.

---

### ORDER 012 — README & Threat Model

**Task:** Write the documentation that makes this project famous.

**Instructions:**
1. Create `README.md` with:
   - One-paragraph project description (lead with the problem, not the tech)
   - Screenshot of dashboard (placeholder until you have one)
   - "One command setup" section with the 5 steps from Section 13
   - Feature list with brief explanation of each
   - Architecture diagram (ASCII or image)
   - Section: "Real threats this detects" — link each feature to a real CVE or incident
   - "Contributing" section with how to add new checks
   - License: MIT
2. Create `THREAT_MODEL.md` with:
   - Section: What is in scope (network-attached IoT devices, firmware analysis, credential testing)
   - Section: What is out of scope (physical attacks, encrypted traffic decryption, zero-days)
   - For each threat in Section 2: Attack surface → attacker capability needed → IronMesh detection method → remediation recommendation
   - Section: Limitations and known gaps (IronMesh is passive where possible, but credential testing is semi-active)
   - Section: Responsible use (IronMesh must only be run on networks you own or have explicit permission to scan)
3. Create `CONTRIBUTING.md`:
   - How to add a new vulnerability check (step-by-step guide with code example)
   - How to update the default credentials list
   - How to add a new alert type

**Done when:** A security engineer who has never seen the project can read the README, understand what it does and why it matters, and have it running in under 10 minutes.

---

## 15. Testing & Demo Strategy

### Local Test Environment

To demo the platform without access to real vulnerable devices, set up a controlled test environment:

```bash
# Run intentionally vulnerable IoT simulators
docker run -d -p 23:23 --name test-telnet vulnerable-device-simulator
docker run -d -p 1883:1883 eclipse-mosquitto  # plaintext MQTT
docker run -d -p 8080:80 dvwa/dvwa            # vulnerable web interface
```

Use this environment to show:
1. Network discovery finding 3 test devices
2. Telnet detection triggering a High alert
3. Default credential scan finding admin/admin on the DVWA container
4. MQTT plaintext detection
5. Risk scores updating after scan completion

### What to Say in Interviews

When asked about IronMesh, open with the problem:
- "820,000 IoT attacks happen every day, mostly through default credentials. Most companies have no visibility into the IoT devices on their network."

Then go straight to a specific technical decision:
- "The interesting engineering problem was building safe default credential testing — you can't just hammer devices with login attempts, you'll lock people out and take down production systems. So I built in a 500ms delay, a max of 50 credential pairs per scan, and lockout detection via HTTP response codes."

Close with impact:
- "I tested it on my own home network and found 3 devices with default credentials I didn't know about."

That is the interview answer that gets offers. Problem → hard technical decision → personal verification.

---

*IronMesh — built to be real, built to get you hired.*