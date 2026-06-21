<div align="center">
  <img src="https://raw.githubusercontent.com/yourusername/seagles/main/assets/logo.png" alt="Seagles Logo" width="200" height="200" style="border-radius: 50%; object-fit: cover; box-shadow: 0 4px 8px rgba(0,0,0,0.1); margin-bottom: 20px;" onerror="this.style.display='none'"/>
  
  <h1>🦅 Seagles</h1>
  <p><b>Advanced, Open-Source IoT Security & Threat Intelligence Platform</b></p>
  <p><i>Find vulnerable devices, expose supply chain implants, and lock down your network before attackers do.</i></p>

  [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
  [![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go)](https://golang.org/)
  [![Python Version](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python)](https://python.org/)
  [![React Version](https://img.shields.io/badge/React-18.x-61DAFB?style=for-the-badge&logo=react)](https://reactjs.org/)
  [![Docker Required](https://img.shields.io/badge/Docker-Required-2496ED?style=for-the-badge&logo=docker)](https://www.docker.com/)
  [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=for-the-badge)](http://makeapullrequest.com)
  [![Build Status](https://img.shields.io/badge/build-passing-brightgreen?style=for-the-badge)]()
  [![Security Scans](https://img.shields.io/badge/security-audited-blue?style=for-the-badge)]()
</div>

<br />

<details>
<summary><b>📖 Table of Contents (Click to expand)</b></summary>

1. [Introduction](#-introduction)
2. [Why Seagles?](#-why-seagles)
3. [Key Features](#-key-features)
4. [What It Detects](#-what-it-detects)
5. [System Architecture](#-system-architecture)
    - [Frontend (React)](#frontend-react)
    - [Backend (Go)](#backend-go)
    - [Firmware Analyzer (Python)](#firmware-analyzer-python)
    - [Database (PostgreSQL)](#database-postgresql)
6. [Getting Started](#-getting-started)
    - [Prerequisites](#prerequisites)
    - [Quick Start (Docker)](#quick-start-docker)
    - [Manual Installation](#manual-installation)
7. [Advanced Configuration](#-advanced-configuration)
    - [Environment Variables](#environment-variables)
    - [Nmap Tuning](#nmap-tuning)
8. [API Reference & Usage](#-api-reference--usage)
9. [Risk Scoring Algorithm](#-risk-scoring-algorithm)
10. [Threat Modeling](#-threat-modeling)
11. [Performance Tuning](#-performance-tuning)
12. [Contributing to Seagles](#-contributing-to-seagles)
13. [Troubleshooting & FAQ](#-troubleshooting--faq)
14. [Responsible Use & Legal Disclaimer](#-responsible-use--legal-disclaimer)
15. [License](#-license)

</details>

---

## 🌟 Introduction

With over **820,000 IoT cyberattacks occurring daily**, connected devices—from security cameras and smart thermostats to industrial SCADA systems—remain the softest underbelly of modern network infrastructure. Traditional vulnerability scanners often miss the nuances of IoT devices, lacking the specialized protocol detection, firmware analysis, and default credential testing required to secure these embedded systems.

**Seagles (formerly IronMesh)** is an enterprise-grade, fully open-source IoT security posture management platform. It is designed to autonomously discover network-visible IoT devices, deeply fingerprint their operating systems and running services, and rigorously assess their risk posture using a combination of active network probing, CISA KEV cross-referencing, and advanced firmware entropy analysis.

---

## 🎯 Why Seagles?

Most network scanners stop at identifying an IP address and an open port. Seagles goes five steps further:
1. **It identifies the device** (Vendor, OS, MAC, Hostname).
2. **It interrogates the protocols** (Modbus, ADB, RTSP, MQTT).
3. **It attempts safe, rate-limited credential brute-forcing** (testing the top 100 default IoT passwords).
4. **It matches CVEs against the CISA Known Exploited Vulnerabilities (KEV) catalog.**
5. **It dissects firmware**, looking for packed malware or supply chain backdoors using Shannon entropy and Binwalk signature analysis.

The result is a consolidated, actionable **0.0 to 10.0 Risk Score** for every device on your network.

---

## ✨ Key Features

- **Autonomous Network Discovery**: Sweep large subnets asynchronously using parallelized Nmap processes.
- **Deep Service Fingerprinting**: Detect insecure or industrial protocols that should never be exposed (e.g., Modbus, Telnet, ADB).
- **Default Credential Auditing**: Safely test network services (SSH, Telnet, HTTP Basic) against known IoT default credential lists (e.g., Mirai botnet dictionaries).
- **CISA KEV Integration**: Automatically ingest the US government's KEV catalog and flag devices vulnerable to actively exploited zero-days.
- **Firmware Entropy Analysis**: Offload suspicious firmware binaries to a dedicated Python microservice to calculate Shannon entropy and extract suspicious hardcoded strings (e.g., `rm -rf /`, backdoors).
- **TLS Posture Assessment**: Validate certificate expiration, weak ciphers (RC4, DES), and deprecated protocols (TLS 1.0/1.1).
- **Real-Time Alerting Engine**: A dedicated goroutine engine to deduplicate and dispatch alerts based on network changes, new devices, and critical vulnerabilities.
- **Beautiful React Dashboard**: A Tailwind-powered, responsive UI with real-time risk charts and telemetry.

---

## 🛡️ What It Detects

| Threat Vector | Real-World Example | How Seagles Detects & Mitigates It |
|---|---|---|
| **Default Credentials** | *Mirai Botnet* (820K attacks/day) | Attempts safe authentication against SSH, Telnet, and HTTP using a curated list of IoT defaults. Scores 9.5 Critical if access is gained. |
| **Telnet Exposure** | *Aisuru Botnet* (20+ Tbps DDoS) | Detects open port 23, verifies the protocol banner, and creates a high-priority alert. |
| **Active Zero-Days** | *AVTECH CVE-2024-7029* | Cross-references every discovered CVE against CISA’s active KEV list. |
| **ADB Exposure** | *BadBox 2.0* (10M infected TVs/Boxes) | Interrogates port 5555, reads the ADB banner, and flags as a critical supply chain risk. |
| **Industrial Protocols** | *ICS/SCADA Compromise* | Fingerprints Modbus (502) and BACnet (47808), immediately scoring Critical due to lack of native auth. |
| **Firmware Implants** | *Supply Chain Backdoors* | Performs Shannon entropy analysis. A score > 7.2 strongly indicates encrypted or packed malicious payloads. |
| **Unencrypted MQTT** | *IoT Data Leaks* | Detects port 1883 without TLS wrapping, flagging cleartext broker data transmission. |
| **Exposed Video Feeds**| *Nation-State Surveillance* | Sends RTSP OPTIONS requests. If no 401 Auth challenge is returned, the stream is flagged as public. |

---

## 🏗️ System Architecture

Seagles utilizes a highly decoupled, asynchronous microservices architecture to ensure scalability and fault tolerance.

```text
                                    ┌────────────────────────┐
                                    │     User Browser       │
                                    └───────────┬────────────┘
                                                │
                                    ┌───────────▼────────────┐
                                    │    React Frontend      │
                                    │  (Tailwind, Recharts)  │
                                    └───────────┬────────────┘
                                                │ REST API (JSON)
┌───────────────────────────────────────────────▼───────────────────────────────────────────────┐
│                                       Go Backend Server                                       │
│                                                                                               │
│  ┌────────────────┐    ┌────────────────┐    ┌────────────────┐    ┌───────────────────────┐  │
│  │   API Router   │────▶   Risk Engine  │────▶ Alert Engine   │────▶ CISA KEV Updater      │  │
│  └────────────────┘    └────────────────┘    └────────────────┘    └───────────────────────┘  │
│          │                                                                                    │
│          ▼                                                                                    │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                                  Scanner Subsystem                                      │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                 │  │
│  │  │ Nmap Wrapper │  │ Protocol Det │  │ Cred Tester  │  │ TLS Verifier │                 │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘                 │  │
│  └─────────────────────────────────────────────────────────────────────────────────────────┘  │
└───────────────────────┬──────────────────────────────────────────────┬────────────────────────┘
                        │                                              │
                        │ HTTP POST /analyze                           │ DB Queries
                        ▼                                              ▼
┌───────────────────────────────────────────────┐        ┌────────────────────────────┐
│         Python Firmware Analyzer              │        │   PostgreSQL Database      │
│                                               │        │                            │
│  ┌──────────────┐  ┌──────────────┐           │        │   - devices                │
│  │ Shannon      │  │ Binwalk      │           │───────▶│   - scans                  │
│  │ Entropy      │  │ Signatures   │           │        │   - vulnerabilities        │
│  └──────────────┘  └──────────────┘           │        │   - alerts                 │
│  ┌──────────────┐  ┌──────────────┐           │        │   - firmware               │
│  │ CVE Lookup   │  │ Suspicious   │           │        └────────────────────────────┘
│  │ (NVD API)    │  │ Strings      │           │
│  └──────────────┘  └──────────────┘           │
└───────────────────────────────────────────────┘
```

### Component Breakdown

#### Frontend (React)
- **Framework**: React 18 with TypeScript.
- **Styling**: Tailwind CSS for rapid, utility-first UI development.
- **Routing**: `react-router-dom` v6 for client-side navigation.
- **Data Visualization**: `recharts` for rendering dynamic risk distribution charts and network topologies.

#### Backend (Go)
- **Framework**: Gin (`gin-gonic/gin`) for lightning-fast HTTP routing.
- **Database Driver**: `lib/pq` with highly optimized connection pooling (Max Open: 25, Max Idle: 5).
- **Concurrency**: Heavy use of Goroutines to ensure network scans do not block the API event loop.
- **Scanners**: Native execution wrappers around Nmap, combined with native Go implementations for SSH, Telnet, and HTTP brute-forcing (`golang.org/x/crypto/ssh`).

#### Firmware Analyzer (Python)
- **Framework**: FastAPI running on Uvicorn.
- **Analysis**: Calculates Shannon entropy mathematically, executes `binwalk` signature matching, and extracts strings matching malicious regex patterns (e.g., `nc -l`, `iptables -F`).
- **Integration**: Queries the NIST NVD API for CVE matching based on firmware vendor and version.

#### Database (PostgreSQL)
- **Version**: PostgreSQL 16+.
- **Extensions**: `pgcrypto` for UUID generation.
- **Data Types**: Extensive use of `JSONB` for storing raw Nmap output and flexible metadata, enabling rapid NoSQL-like queries within a relational schema.

---

## 🚀 Getting Started

### Prerequisites

To run Seagles, ensure your host machine has the following installed:
1. **Docker Engine** (v20.10.0+)
2. **Docker Compose** (v2.0+)
3. **Make** (Optional, but highly recommended for convenience)
4. *Operating System*: A Linux host or Linux VM is **strongly recommended**. Docker Desktop on macOS and Windows utilizes a lightweight VM that obscures raw socket access, which can severely limit Nmap's ability to perform accurate OS fingerprinting and MAC address resolution.

### Quick Start (Docker)

Deploying Seagles takes less than 5 minutes using our pre-configured Docker Compose pipeline.

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/seagles.git
   cd seagles
   ```

2. **Configure your environment variables:**
   ```bash
   cp .env.example .env
   ```
   Open `.env` in your favorite editor. The most critical variable to set is your `NETWORK_CIDR`. 
   ```env
   DB_PASSWORD=SuperSecretPassword123!
   NETWORK_CIDR=192.168.1.0/24  # Set this to the subnet you wish to monitor
   NVD_API_KEY=                 # (Optional) Get one free at nvd.nist.gov
   ```

3. **Build and spin up the cluster:**
   ```bash
   make up
   # OR, if you don't have make:
   docker compose up -d --build
   ```

4. **Verify the installation:**
   Wait about 30 seconds for PostgreSQL to initialize, the Go backend to run database migrations, and the Python microservice to start.
   ```bash
   make logs
   # Watch for "Seagles starting..." and "Database connection established"
   ```

5. **Access the Dashboard:**
   Open your web browser and navigate to:
   **[http://localhost:3000](http://localhost:3000)**

### Manual Installation (Development)

If you wish to contribute to Seagles, you may want to run the components directly on your bare-metal host.

<details>
<summary><b>Click here for Manual Setup Instructions</b></summary>

**1. Install System Dependencies (Ubuntu/Debian)**
```bash
sudo apt-get update
sudo apt-get install -y nmap binwalk postgresql python3 python3-pip golang-go nodejs npm
```

**2. Setup PostgreSQL**
```bash
sudo -u postgres psql -c "CREATE DATABASE seagles;"
sudo -u postgres psql -c "CREATE USER seagles WITH PASSWORD 'changeme';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE seagles TO seagles;"
```

**3. Run the Go Backend**
```bash
cd backend
go mod tidy
DATABASE_URL="postgres://seagles:changeme@localhost:5432/seagles?sslmode=disable" go run main.go
```

**4. Run the Python Analyzer**
```bash
cd firmware-analyzer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
DATABASE_URL="postgres://seagles:changeme@localhost:5432/seagles?sslmode=disable" uvicorn main:app --port 8001
```

**5. Run the React Frontend**
```bash
cd frontend
npm install
REACT_APP_API_URL="http://localhost:8080/api/v1" npm start
```
</details>

---

## 🛠️ Advanced Configuration

### Environment Variables

The entire Seagles stack is configurable via environment variables passed to the containers.

| Variable | Service | Default | Description |
|---|---|---|---|
| `DB_PASSWORD` | PostgreSQL / Backend / Analyzer | *Required* | The master password for the database. |
| `NETWORK_CIDR` | Backend | `192.168.1.0/24` | The target subnet for the automated network discovery scanner. |
| `PORT` | Backend | `8080` | The port the Go API server binds to. |
| `NVD_API_KEY` | Backend / Analyzer | `""` | NIST NVD API Key. Drastically improves CVE lookup speed and bypasses strict rate limits. |
| `FIRMWARE_ANALYZER_URL` | Backend | `http://firmware-analyzer:8001` | Internal Docker networking route to the Python microservice. |
| `REACT_APP_API_URL` | Frontend | `/api/v1` | Instructs the React app where to make API calls. In production, this uses relative paths handled by Nginx. |

### Nmap Tuning
To optimize network discovery, Seagles uses specific Nmap flags. By default, it limits retries and enforces strict timeouts to prevent the backend goroutines from hanging indefinitely on dead IPs.

In `backend/scanner/nmap.go`, you will find:
```go
exec.CommandContext(ctx, "nmap", "-sn", cidr, "-oX", "-", "--max-retries", "2", "--host-timeout", "5s")
```
If you are scanning across a slow VPN or a highly congested wireless network, you may need to increase the `--host-timeout` to `15s`.

---

## 📡 API Reference & Usage

Seagles exposes a clean, RESTful JSON API. All responses are wrapped in a standard envelope:
```json
{
  "data": { ... },
  "error": null
}
```

### Trigger a Subnet Discovery Scan
Discovers new devices and updates `last_seen` timestamps for existing ones.
```bash
curl -X POST http://localhost:8080/api/v1/scan/network
```

### Trigger a Deep Device Scan
Initiates an Nmap deep scan, credential brute-force, and protocol check against a specific device UUID.
```bash
curl -X POST http://localhost:8080/api/v1/devices/<DEVICE_UUID>/scan
```

### Get Platform Statistics
Fetches real-time counts of critical vulnerabilities, online devices, and average network risk.
```bash
curl -s http://localhost:8080/api/v1/stats | jq .
```

---

## 🧮 Risk Scoring Algorithm

Seagles does not use arbitrary High/Medium/Low tags. Instead, it utilizes a deterministic scoring algorithm to generate a `0.0` to `10.0` risk score (resembling CVSS), providing a granular view of device posture.

The algorithm (found in `backend/risk/scorer.go`) works by aggregating active risk factors:

1. **Base Penalties (Authentication & Protocols):**
   - Default Credentials Active: **+4.0**
   - Telnet Exposed: **+3.0**
   - ADB (Android Debug) Exposed: **+3.5**
   - Modbus Protocol Detected: **+2.5**
   - Unauthenticated RTSP: **+2.0**
   - Weak/Deprecated TLS: **+1.5**

2. **Vulnerability Penalties:**
   - Base CVE Penalty: `+0.5` points per known CVE (Capped at `+3.0` maximum)
   - CISA KEV Match Penalty: `+2.0` points per KEV match (Capped at `+4.0` maximum)

3. **Firmware & Health:**
   - High Entropy Firmware (Score > 7.2): **+2.0**
   - Days Since Last Scan: Scales up to **+1.0** based on staleness.

*Total scores are clamped mathematically to a maximum of 10.0.*

**Severity Mapping:**
- `0.0 - 2.9`: **LOW**
- `3.0 - 5.9`: **MEDIUM**
- `6.0 - 7.9`: **HIGH**
- `8.0 - 10.0`: **CRITICAL**

---

## 🛑 Threat Modeling

Seagles is built with a specific operational threat model in mind. 

### In-Scope Protections
- **Network-Visible Attack Surface:** Identification of ports and services accessible from the local network segment.
- **Authentication Weaknesses:** Detection of factory-default or hardcoded credentials.
- **Supply Chain Compromise:** Identification of malicious implants in vendor firmware updates.
- **Protocol Abuse:** Flagging IoT devices that utilize inherently insecure M2M protocols (Cleartext MQTT, Modbus).

### Out-of-Scope (Limitations)
- **Zero-Day Discovery:** Seagles relies on known CVEs and signatures; it does not fuzz binaries to find new memory corruption bugs.
- **Encrypted Traffic Interception:** Seagles does not perform Man-in-the-Middle (MitM) TLS inspection.
- **Physical Access Attacks:** Seagles cannot detect JTAG/UART tampering or malicious USB hardware.

*For a full breakdown of the Seagles operational threat model, please read the `THREAT_MODEL.md` file located in the repository root.*

---

## 🏎️ Performance Tuning

If you are running Seagles on a massive enterprise subnet (e.g., a `/16` network), you will need to tune the PostgreSQL connection pool and Go garbage collection.

1. **Database Connections:** In `backend/db/db.go`, increase `db.SetMaxOpenConns(25)` to `100+` to handle hundreds of concurrent Goroutines writing scan results.
2. **File Descriptors:** Ensure your host OS allows for a high number of open file descriptors, as Go's `net/http` and the SSH credential tester will consume them rapidly during a mass scan.
   ```bash
   ulimit -n 65535
   ```
3. **Nmap Parallelism:** The Go backend currently launches Nmap as a child process. For massive networks, consider rewriting the discovery logic to chunk the CIDR block and queue the scans via a message broker (like Redis/Celery or RabbitMQ).

---

## 🤝 Contributing to Seagles

We welcome contributions from the open-source cybersecurity community! Whether you're adding a new protocol detector, fixing a React bug, or expanding our default credential dictionary, your help is appreciated.

### How to Add a New Security Check

1. **Protocol Scanner**: Open `backend/scanner/protocols.go`. Write a new function that accepts an IP and port, tests the protocol, and returns a `ProtocolFinding` struct.
2. **Alert Type**: Open `backend/alerts/types.go` and add a new constant for your alert (e.g., `AlertFTPAnonymous = "ftp_anonymous"`).
3. **Risk Scoring**: Add a boolean flag to the `RiskFactors` struct in `risk/scorer.go` and update the `CalculateRiskScore` math to penalize the device.
4. **Pull Request**: Ensure your code is formatted (`go fmt`) and submit a PR with a description of the threat you are mitigating.

Please see our `CONTRIBUTING.md` file for full coding standards and branch naming conventions.

---

## ❓ Troubleshooting & FAQ

**Q: My devices are showing up, but they all have MAC addresses of `null` or empty strings.**
> **A:** This is a Docker limitation on Windows and macOS. To resolve MAC addresses, Nmap must send raw ARP requests. Docker Desktop's underlying virtual machine isolates the container's network stack, preventing ARP from reaching your physical LAN. To fix this, run Seagles natively on a Linux host using `network_mode: host`.

**Q: Firmware analysis is taking a very long time and returning errors.**
> **A:** The NIST NVD API aggressively rate-limits requests from IP addresses without an API key (down to roughly 1 request every 6 seconds). Obtain a free API key from NIST and add it to your `.env` file as `NVD_API_KEY`.

**Q: Can Seagles scan over the internet (WAN)?**
> **A:** Technically yes, if you provide public IPs instead of a local CIDR block. However, **this is highly discouraged and likely illegal** without prior written consent from the network owner. Seagles is designed for internal LAN/VLAN posture management.

**Q: The React UI isn't updating after a scan finishes.**
> **A:** The Dashboard relies on a 30-second polling interval `setInterval` hook. If you want instant updates, you can manually refresh the page, or contribute a WebSocket implementation to our Go router!

---

## ⚖️ Responsible Use & Legal Disclaimer

**WARNING:** Seagles is a powerful, active security auditing tool. It performs aggressive network port scanning, interacts with active services, and automatically attempts to authenticate using dictionary attacks (credential brute-forcing).

- **Authorization is Mandatory:** You must strictly use this software on networks, devices, and infrastructure that you explicitly own, or for which you have obtained explicit, written, and legally binding authorization to audit.
- **Potential for Disruption:** IoT devices are notoriously fragile. Aggressive Nmap scanning or rapid SSH authentication attempts may cause older embedded devices to crash, freeze, or enter denial-of-service states.
- **No Liability:** The authors, contributors, and maintainers of the Seagles project assume **zero liability** and are not responsible for any misuse, data loss, network downtime, or legal repercussions resulting from the use of this software. 

**By using Seagles, you acknowledge and agree to these terms.**

---

## 📄 License

This project is licensed under the **MIT License**. 

You are free to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, provided that the original copyright notice and permission notice are included in all copies or substantial portions of the Software.

See the [LICENSE](LICENSE) file for full details.

<br/>
<div align="center">
  <i>"Visibility is the first step to security."</i>
</div>
