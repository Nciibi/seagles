# 🛡️ IronMesh

**Open-source IoT security platform. Find vulnerable devices before attackers do.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.22-00ADD8.svg)](https://go.dev)
[![Docker](https://img.shields.io/badge/Docker-required-2496ED.svg)](https://docker.com)

---

## What this does

820,000 IoT attacks happen every day. Most are through default credentials that nobody changed. Most companies have no idea what IoT devices are on their network, let alone whether they're secure.

IronMesh discovers every IoT device on your network, scans them for real CVEs, tests for default credentials (admin/admin, root/root — the ones botnets use), analyzes firmware for malware indicators, and scores each device's risk from 0 to 10. When something is wrong, you know immediately.

---

## Setup in 5 minutes

```bash
git clone https://github.com/yourusername/ironmesh
cd ironmesh
cp .env.example .env
# Edit .env: set your network CIDR (e.g. 192.168.1.0/24)
docker compose up -d
open http://localhost:3000
```

Trigger your first network scan:
```bash
curl -X POST http://localhost:8080/api/v1/scan/network
```

---

## What it detects

| Threat | Real-world Example | How IronMesh Catches It |
|---|---|---|
| **Default credentials** | Mirai botnet (820K attacks/day) | Tests top-100 credential pairs per device, scores 9.5 CVSS if found |
| **Telnet exposure** | Aisuru botnet (20+ Tbps DDoS) | Detects open port 23, creates Critical alert immediately |
| **CISA KEV matches** | AVTECH CVE-2024-7029 | Cross-references every CVE against CISA's active exploit list (1100+ entries) |
| **ADB exposure** | BadBox 2.0 (10M pre-infected devices) | Detects port 5555 ADB banner, flags as supply chain risk |
| **Industrial protocols** | April 2026 ICS advisories (Honeywell, Mitsubishi) | Fingerprints Modbus (502) and BACnet (47808), scores Critical |
| **Firmware malware** | Supply chain implants | Shannon entropy analysis: score >7.2 = encrypted/packed payload |
| **Unencrypted MQTT** | 24% of IoT apps have TLS issues | Detects port 1883 without TLS, flags cleartext broker |
| **Unauthenticated RTSP** | Nation-state camera surveillance (Feb 2026) | RTSP OPTIONS without auth challenge = exposed stream |
| **Weak TLS** | Deprecated protocol attacks | Tests TLS 1.0/1.1 support, flags weak ciphers (RC4, DES, MD5) |

---

## Architecture

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

---

## Requirements

- **Docker** and **Docker Compose** (v2+)
- **Linux host** recommended for full nmap scanner functionality
  - On Mac/Windows (Docker Desktop): basic scanning works, but `network_mode: host` behaves differently
  - For full scanner capability, use a Linux VM or dedicated machine
- **2GB RAM**, **10GB disk**
- **Optional**: NVD API key (free at [nvd.nist.gov](https://nvd.nist.gov)) for faster CVE lookups

---

## Configuration

| Variable | Description | Default |
|---|---|---|
| `DB_PASSWORD` | PostgreSQL password | `changeme_strong_password_here` |
| `NETWORK_CIDR` | Network range to scan (e.g. `192.168.1.0/24`) | `192.168.1.0/24` |
| `NVD_API_KEY` | NIST NVD API key for faster CVE lookups | *(empty — uses public rate limit)* |
| `PORT` | Backend API port | `8080` |
| `FIRMWARE_ANALYZER_URL` | Firmware analyzer service URL | `http://firmware-analyzer:8001` |

---

## Adding new checks

1. **Add a vulnerability check function** in `backend/scanner/` — return a `ProtocolFinding` struct
2. **Call `alerts.CreateAlert()`** with the appropriate type constant from `alerts/engine.go`
3. **Add a risk factor** to the `RiskFactors` struct in `risk/scorer.go`
4. **Update `CalculateRiskScore()`** with the new factor's point value
5. **Open a PR** with a test and update the README "What it detects" table

---

## Risk Scoring

Every device gets a 0–10 risk score. The scoring is additive:

| Factor | Points |
|---|---|
| Default credentials found | +4.0 |
| ADB exposed | +3.5 |
| Telnet open | +3.0 |
| Modbus detected | +2.5 |
| High-entropy firmware | +2.0 |
| KEV match | +2.0 per match (max +4.0) |
| Unauthenticated RTSP | +2.0 |
| Weak TLS | +1.5 |
| Plaintext MQTT | +1.5 |
| HTTP management | +1.0 |
| Firmware outdated | +1.0 |
| Known CVEs | +0.5 per CVE (max +3.0) |

**Score ranges:** 0–2.9 Low (green) · 3–5.9 Medium (blue) · 6–7.9 High (amber) · 8–10 Critical (red)

---

## Responsible Use

⚠️ **IronMesh performs active network scanning and credential testing.** Only use it on networks you own or have explicit written permission to test. Unauthorized scanning may be illegal in your jurisdiction.

Built-in safety measures:
- 500ms delay between credential attempts
- Maximum 50 credential pairs per device per scan
- Lockout detection via HTTP 429 and response body analysis
- Full audit logging of every credential test

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

*IronMesh — built to be real, built to find threats before attackers do.*
