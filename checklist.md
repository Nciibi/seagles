# IronMesh (Seagles) Implementation Checklist

## Completed

- [x] **PROMPT 001 — Project Scaffolding**
  - [x] Directory structure creation
  - [x] Go module initialization and dependencies
  - [x] `.env.example`, `config.go`, `main.go`, and `default-credentials.txt`

- [x] **PROMPT 002 — Database & Migrations**
  - [x] Database connection setup (`db/db.go`)
  - [x] Migrations runner
  - [x] Initial SQL migrations (001 to 005)
  - [x] Database models (`device.go`, `scan.go`, `vulnerability.go`, `firmware.go`, `alert.go`)

- [x] **PROMPT 003 — Go API Server**
  - [x] Router setup (`api/router.go`)
  - [x] Stats API (`api/risks.go`)
  - [x] Devices API (`api/devices.go`)
  - [x] Scans API (`api/scans.go`)
  - [x] Vulnerabilities API (`api/vulnerabilities.go`)
  - [x] Alerts API (`api/alerts.go`)
  - [x] Firmware API (`api/firmware.go`)
  - [x] KEV Status API (`api/kev.go`)

## Partially Completed

- [x] **PROMPT 004 — Network Discovery Scanner**
  - [x] Nmap XML parsing and execution (`scanner/nmap.go`)
  - [ ] Protocol detection (`scanner/protocols.go`)
  - [ ] TLS analysis (`scanner/tls.go`)

## Left to be Done

- [ ] **PROMPT 005 — Default Credential Scanner**
  - [ ] Credentials loader
  - [ ] SSH credential tester
  - [ ] HTTP Basic Auth tester
  - [ ] Telnet credential tester

- [ ] **PROMPT 006 — CISA KEV Integration**
  - [ ] KEV struct models
  - [ ] Downloader and cache loader
  - [ ] Check/flag KEV utility function
  - [ ] Updater goroutine

- [ ] **PROMPT 007 — Risk Scoring Engine**
  - [ ] Risk factor calculation (`risk/scorer.go`)
  - [ ] Database risk updates (`risk/updater.go`)

- [ ] **PROMPT 008 — Alerting Engine**
  - [ ] Alert deduplication and insertion (`alerts/engine.go`)
  - [ ] Alert type constants (`alerts/types.go`)
  - [ ] Alert monitor background goroutine

- [ ] **PROMPT 009 — Firmware Analyzer (Python Microservice)**
  - [ ] Entropy analysis (`entropy.py`)
  - [ ] Binwalk runner (`binwalk_runner.py`)
  - [ ] CVE lookup (`cve_lookup.py`)
  - [ ] FastAPI main application (`main.py`)
  - [ ] Dockerfile and dependencies

- [ ] **PROMPT 010 — React Frontend**
  - [ ] API Client (`src/api/client.ts`)
  - [ ] Dashboard Page (`src/pages/Dashboard.tsx`)
  - [ ] Devices and Device Detail Pages
  - [ ] Vulnerabilities Page
  - [ ] UI Components (AlertFeed, RiskScore, etc.)
  - [ ] Nginx configuration and Dockerfile

- [ ] **PROMPT 011 — Docker Compose & Final Wiring**
  - [ ] `docker-compose.yml` with postgres, backend, firmware-analyzer, frontend
  - [ ] Backend Dockerfile
  - [ ] Makefile shortcuts

- [ ] **PROMPT 012 — README & Threat Model**
  - [ ] `README.md`
  - [ ] `THREAT_MODEL.md`
  - [ ] `CONTRIBUTING.md`
