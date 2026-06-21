# IronMesh — Agent Prompts
### Copy-paste these into Claude Code, Cursor, or any coding agent. One prompt per order. Do not skip steps.

---

## How to use this file

1. Open your agent (Claude Code terminal, Cursor, etc.)
2. Copy the entire prompt block for the current order
3. Paste it and run
4. Wait for the "done when" confirmation before moving to the next
5. If something fails, paste the error back into the agent with: "Fix this error and try again"

> ⚠️ Always run orders in sequence. Later orders depend on earlier ones.

---

## PROMPT 001 — Project Scaffolding

```
You are building IronMesh, an open-source IoT security platform. Your job in this step is to create the full project scaffold.

Create the following directory structure exactly:

ironmesh/
├── README.md
├── THREAT_MODEL.md
├── docker-compose.yml
├── .env.example
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
│   ├── kev/
│   │   └── updater.go
│   └── models/
│       ├── device.go
│       ├── scan.go
│       ├── vulnerability.go
│       ├── firmware.go
│       └── alert.go
├── firmware-analyzer/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py
│   ├── entropy.py
│   ├── cve_lookup.py
│   └── binwalk_runner.py
├── frontend/
│   ├── package.json
│   ├── tsconfig.json
│   └── src/
│       ├── main.tsx
│       ├── App.tsx
│       ├── api/
│       │   └── client.ts
│       ├── components/
│       │   ├── DeviceInventory.tsx
│       │   ├── VulnScanner.tsx
│       │   ├── FirmwarePanel.tsx
│       │   ├── RiskScore.tsx
│       │   ├── AlertFeed.tsx
│       │   └── NetworkMap.tsx
│       └── pages/
│           ├── Dashboard.tsx
│           ├── Devices.tsx
│           ├── Vulnerabilities.tsx
│           └── Firmware.tsx
└── data/
    └── default-credentials.txt

Then do the following:

1. Run: go mod init github.com/yourusername/ironmesh inside the backend/ directory
2. Add these Go dependencies to go.mod:
   - github.com/gin-gonic/gin v1.10.0
   - github.com/lib/pq v1.10.9
   - github.com/google/uuid v1.6.0
   - golang.org/x/crypto v0.23.0
   - github.com/joho/godotenv v1.5.1
3. Run go mod tidy
4. Create .env.example with this exact content:
   DB_PASSWORD=changeme_strong_password_here
   NETWORK_CIDR=192.168.1.0/24
   NVD_API_KEY=
5. Create backend/config/config.go that reads these env vars and returns a Config struct with fields: DatabaseURL, Port, NetworkCIDR, NVDAPIKey
6. Create a minimal backend/main.go that imports the config package, loads env, prints "IronMesh starting..." and exits cleanly
7. Create data/default-credentials.txt with these 50 entries (one per line, format username:password):
   admin:admin
   admin:password
   admin:1234
   admin:12345
   admin:123456
   admin:(blank)
   root:root
   root:password
   root:1234
   root:(blank)
   admin:admin123
   user:user
   guest:guest
   admin:pass
   admin:Password1
   support:support
   admin:support
   supervisor:supervisor
   Administrator:admin
   Administrator:password
   ubnt:ubnt
   pi:raspberry
   admin:888888
   admin:666666
   admin:default
   test:test
   demo:demo
   service:service
   manager:manager
   operator:operator
   admin:system
   admin:1111
   admin:0000
   root:admin
   root:123456
   root:pass
   admin:admin1
   admin:password123
   admin:admin@123
   admin:Admin123
   admin:qwerty
   admin:letmein
   admin:welcome
   admin:changeme
   admin:abc123
   camera:camera
   ftp:ftp
   anonymous:anonymous
   netgear:password
   linksys:admin

Confirm when all files and directories are created and go mod tidy completes without errors.
```

---

## PROMPT 002 — Database & Migrations

```
You are continuing to build IronMesh, an IoT security platform. The project scaffold already exists. Your job now is to set up the PostgreSQL database layer.

Create the following files:

--- backend/db/db.go ---
Package db. Implement:
- A Connect(databaseURL string) *sql.DB function that opens a PostgreSQL connection using lib/pq, sets MaxOpenConns to 25, MaxIdleConns to 5, ConnMaxLifetime to 5 minutes, and calls db.Ping() to verify the connection. Fatal log if connection fails.
- A RunMigrations(db *sql.DB) function that reads all .sql files from the db/migrations/ directory in alphabetical order and executes them in sequence. Log each migration file name as it runs. Fatal if any migration fails.

--- backend/db/migrations/001_create_devices.sql ---
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address INET NOT NULL,
    mac_address MACADDR,
    hostname TEXT,
    vendor TEXT,
    device_type TEXT DEFAULT 'unknown',
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

CREATE INDEX IF NOT EXISTS idx_devices_risk ON devices(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_devices_active ON devices(is_active, last_seen DESC);

--- backend/db/migrations/002_create_scans.sql ---
CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'running',
    scan_type TEXT NOT NULL DEFAULT 'full',
    open_ports JSONB,
    services JSONB,
    scan_output TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_device ON scans(device_id, started_at DESC);

--- backend/db/migrations/003_create_vulnerabilities.sql ---
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    cve_id TEXT,
    cvss_score NUMERIC(3,1),
    severity TEXT NOT NULL DEFAULT 'medium',
    title TEXT NOT NULL,
    description TEXT,
    affected_component TEXT,
    remediation TEXT,
    is_kev BOOLEAN DEFAULT FALSE,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    is_resolved BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_vulns_device ON vulnerabilities(device_id, severity);
CREATE INDEX IF NOT EXISTS idx_vulns_kev ON vulnerabilities(is_kev) WHERE is_kev = TRUE;
CREATE INDEX IF NOT EXISTS idx_vulns_unresolved ON vulnerabilities(is_resolved) WHERE is_resolved = FALSE;

--- backend/db/migrations/004_create_firmware.sql ---
CREATE TABLE IF NOT EXISTS firmware (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    version TEXT,
    vendor TEXT,
    checksum TEXT,
    file_path TEXT,
    analyzed_at TIMESTAMPTZ,
    entropy_score NUMERIC(5,4),
    has_default_creds BOOLEAN DEFAULT FALSE,
    has_telnet BOOLEAN DEFAULT FALSE,
    has_backdoor_indicators BOOLEAN DEFAULT FALSE,
    strings_of_interest TEXT[],
    cve_matches TEXT[],
    analysis_status TEXT DEFAULT 'pending',
    analysis_report JSONB
);

--- backend/db/migrations/005_create_alerts.sql ---
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    severity TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    triggered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at TIMESTAMPTZ,
    is_acknowledged BOOLEAN DEFAULT FALSE,
    metadata JSONB
);

CREATE INDEX IF NOT EXISTS idx_alerts_device ON alerts(device_id, triggered_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_unacked ON alerts(is_acknowledged, triggered_at DESC) WHERE is_acknowledged = FALSE;

--- backend/models/ files ---
Create Go structs for each table:
- models/device.go: Device struct with all fields, json tags matching snake_case column names, db tags for database/sql scanning
- models/scan.go: Scan struct
- models/vulnerability.go: Vulnerability struct with IsKEV bool field tagged as is_kev
- models/firmware.go: Firmware struct with EntropyScore float64
- models/alert.go: Alert struct with AlertType and Severity string fields

Update backend/main.go to:
- Load .env file using godotenv
- Call db.Connect() with the DATABASE_URL from config
- Call db.RunMigrations()
- Print "Migrations complete" and exit

Test by running: docker run -e POSTGRES_PASSWORD=test -e POSTGRES_DB=ironmesh -p 5432:5432 postgres:16-alpine
Then: DATABASE_URL="postgres://postgres:test@localhost:5432/ironmesh?sslmode=disable" go run main.go

Confirm all 5 migration files execute without errors.
```

---

## PROMPT 003 — Go API Server

```
You are continuing to build IronMesh. The database schema is set up. Now build the full REST API server.

The API must use the gin-gonic/gin framework. All responses use this envelope:
- Success: {"data": <payload>, "error": null}
- Error:   {"data": null, "error": "<message>"}

Create a helper function in api/router.go:
  func success(c *gin.Context, data interface{}) { c.JSON(200, gin.H{"data": data, "error": nil}) }
  func fail(c *gin.Context, status int, msg string) { c.JSON(status, gin.H{"data": nil, "error": msg}) }

--- api/router.go ---
Create NewRouter(db *sql.DB, cfg *config.Config) *gin.Engine that:
- Sets gin to release mode in production
- Adds CORS middleware: allow all origins, methods GET/POST/PUT/PATCH/DELETE, headers Content-Type/Authorization
- Mounts all routes under /api/v1/
- Returns the engine

Routes to register:
  GET    /api/v1/stats
  GET    /api/v1/devices
  GET    /api/v1/devices/:id
  DELETE /api/v1/devices/:id
  POST   /api/v1/devices/:id/scan
  GET    /api/v1/devices/:id/risk-breakdown
  GET    /api/v1/scans
  GET    /api/v1/scans/:id
  GET    /api/v1/vulnerabilities
  PATCH  /api/v1/vulnerabilities/:id/resolve
  GET    /api/v1/firmware
  POST   /api/v1/firmware/:id/analyze
  GET    /api/v1/alerts
  POST   /api/v1/alerts/:id/ack
  GET    /api/v1/kev/status
  POST   /api/v1/scan/network

--- api/risks.go ---
Implement GET /api/v1/stats handler that runs this query and returns the result:
SELECT
  COUNT(*) FILTER (WHERE is_active) as total_devices,
  COUNT(*) FILTER (WHERE is_active AND last_seen > NOW() - INTERVAL '5 minutes') as online_devices,
  AVG(risk_score) FILTER (WHERE is_active) as avg_risk_score
FROM devices;

Then separately query:
SELECT COUNT(*) FROM vulnerabilities WHERE is_resolved = FALSE AND severity = 'critical'  -- as critical_vulns
SELECT COUNT(*) FROM vulnerabilities WHERE is_resolved = FALSE AND severity = 'high'       -- as high_vulns
SELECT COUNT(*) FROM vulnerabilities WHERE is_resolved = FALSE AND severity = 'medium'     -- as medium_vulns
SELECT COUNT(*) FROM vulnerabilities WHERE is_resolved = FALSE AND is_kev = TRUE           -- as kev_vulns
SELECT COUNT(*) FROM alerts WHERE is_acknowledged = FALSE                                  -- as open_alerts
SELECT COUNT(*) FROM firmware WHERE analysis_status = 'complete' AND entropy_score > 7.2  -- as suspicious_firmware

Return all as a single JSON object.

--- api/devices.go ---
Implement:
1. GET /devices — query all devices, support query params: ?risk_min=float, ?risk_max=float, ?device_type=string, ?page=int (default 1), ?limit=int (default 50). Order by risk_score DESC.
2. GET /devices/:id — return device + its latest scan + count of open vulnerabilities
3. DELETE /devices/:id — set is_active = false, return 200
4. GET /devices/:id/risk-breakdown — return a JSON object showing which risk factors are active for this device (query vulnerabilities and firmware tables to build the breakdown)

--- api/vulnerabilities.go ---
Implement:
1. GET /vulnerabilities — list all vulns. Query params: ?severity=string, ?device_id=uuid, ?is_kev=bool, ?is_resolved=bool. Order by cvss_score DESC, discovered_at DESC.
2. PATCH /vulnerabilities/:id/resolve — set is_resolved=true, resolved_at=NOW()

--- api/alerts.go ---
Implement:
1. GET /alerts — list alerts. Query params: ?severity=string, ?device_id=uuid, ?is_acknowledged=bool. Order by triggered_at DESC. Default limit 100.
2. POST /alerts/:id/ack — set is_acknowledged=true, acknowledged_at=NOW()

--- api/scans.go ---
Implement:
1. GET /scans — list scans ordered by started_at DESC, limit 100
2. GET /scans/:id — return single scan with its device info joined
3. POST /devices/:id/scan — for now, create a scan record with status="running" and return the scan ID. Log "Scan triggered for device <id>". The actual scanner will be wired in ORDER 004.
4. POST /scan/network — for now, log "Network scan triggered" and return {"message": "network scan started"}. The actual scanner will be wired in ORDER 004.

--- api/firmware.go ---
Implement:
1. GET /firmware — list all firmware records with their device info joined
2. POST /firmware/:id/analyze — set analysis_status="pending", log "Firmware analysis triggered for <id>", return 200. The actual analyzer will be wired in ORDER 009.

Update main.go to start the gin server on the configured port.

Confirm by running the server and testing:
curl http://localhost:8080/api/v1/stats
curl http://localhost:8080/api/v1/devices
curl http://localhost:8080/api/v1/alerts

All must return {"data": ..., "error": null}.
```

---

## PROMPT 004 — Network Discovery Scanner

```
You are continuing to build IronMesh. The API server is running. Now build the network scanner engine.

Prerequisite: nmap must be installed on the system. If running in Docker, it will be installed via the Dockerfile. For local development, install it with: sudo apt-get install nmap (Linux) or brew install nmap (Mac).

--- scanner/nmap.go ---
Create these types:
  type Host struct {
      IP        string
      MAC       string
      Hostname  string
      Vendor    string
      OSMatch   string
      OpenPorts []Port
      Services  map[int]Service
      RawXML    []byte
  }

  type Port struct {
      Number   int
      Protocol string
      State    string
  }

  type Service struct {
      Name    string
      Version string
      Banner  string
  }

  type ScanResult struct {
      Host     Host
      Duration time.Duration
      Error    error
  }

Implement:
1. DiscoverHosts(cidr string) ([]string, error)
   - Runs: nmap -sn <cidr> -oX - --max-retries 2 --host-timeout 5s
   - Parses the XML output (use encoding/xml)
   - Returns slice of live IP addresses
   - Times out the entire operation after 5 minutes

2. DeepScan(ip string) (*ScanResult, error)
   - Runs: nmap -sV -sC -O -p 22,23,80,443,554,1883,1884,5555,8883,47808,502 --script=banner,http-title -oX - --host-timeout 60s <ip>
   - Parses full XML result into ScanResult struct
   - Returns error if nmap is not found in PATH (error message: "nmap not found: please install nmap")
   - Times out after 90 seconds

XML parsing: nmap XML structure has <nmaprun> > <host> > <address>, <ports> > <port> > <state> and <service> elements. Parse these fields: addr (IP), addrtype (ipv4/mac), hostname, osclass accuracy+osfamily, port portid, port state state, service name/version/extrainfo.

--- scanner/protocols.go ---
Create type ProtocolFinding struct with fields: Protocol, Port, Risk (string: "critical"/"high"/"medium"), Description, Evidence string.

Implement DetectProtocols(ip string, openPorts []int) []ProtocolFinding:
- Check if port 23 is in openPorts → attempt TCP connect + read banner (timeout 3s) → if banner contains "login" or "telnet" or connection succeeds: add finding {Protocol:"Telnet", Port:23, Risk:"critical", Description:"Telnet exposes credentials in plaintext"}
- Check if port 5555 is in openPorts → attempt TCP connect + read 4 bytes → if bytes are "CNXN" or connection accepted: add finding {Protocol:"ADB", Port:5555, Risk:"critical", Description:"Android Debug Bridge exposed - BadBox 2.0 indicator"}
- Check if port 1883 is in openPorts → attempt TCP connect, send MQTT CONNECT packet (bytes: 10 0d 00 04 4d 51 54 54 04 02 00 3c 00 01 00), read response → if response starts with byte 0x20: add finding {Protocol:"MQTT-plaintext", Port:1883, Risk:"high", Description:"MQTT broker without TLS - credentials transmitted in cleartext"}
- Check if port 502 is in openPorts → attempt TCP connect, send Modbus request (bytes: 00 01 00 00 00 06 01 11 00 00 00 00) → if any response received: add finding {Protocol:"Modbus", Port:502, Risk:"critical", Description:"Industrial Modbus protocol detected - no authentication by design"}
- Check if port 554 is in openPorts → send HTTP OPTIONS request, check if response is valid RTSP (200 OK) without requiring auth (no 401 response) → if unauthenticated: add finding {Protocol:"RTSP-unauth", Port:554, Risk:"high", Description:"Camera stream accessible without authentication"}

--- scanner/tls.go ---
Create type TLSResult struct with fields: Host string, Port int, SupportsTLS10 bool, SupportsTLS11 bool, SupportsTLS12 bool, SupportsTLS13 bool, CertExpiry time.Time, CertExpired bool, SelfSigned bool, WeakCiphers []string.

Implement CheckTLS(host string, port int) TLSResult:
- For each TLS version (1.0, 1.1, 1.2, 1.3): attempt tls.Dial with that specific version configured as both min and max version, timeout 5s. Record which versions are supported.
- On successful TLS 1.2+ connection: extract certificate chain, check expiry, check if self-signed (issuer == subject), note the cipher suite used
- Weak cipher check: flag if cipher suite contains RC4, DES, 3DES, or MD5 in the name

--- Wire scanner into API ---
Update api/scans.go POST /devices/:id/scan to:
1. Create a scan record in the database with status="running"
2. Launch a goroutine that:
   a. Calls scanner.DeepScan(device.IPAddress)
   b. Calls scanner.DetectProtocols(ip, openPorts)
   c. Calls scanner.CheckTLS(ip, 443) if port 443 is open
   d. Saves open_ports and services to the scan record
   e. Creates vulnerability records for each ProtocolFinding
   f. Sets scan status="complete" and completed_at=NOW()
   g. Logs "Scan complete for <ip>: found <n> open ports, <n> protocol findings"
3. Return the scan ID immediately (don't wait for goroutine)

Update api/scans.go POST /scan/network to:
1. Call scanner.DiscoverHosts(cfg.NetworkCIDR) 
2. For each discovered IP: upsert into devices table (INSERT ... ON CONFLICT (ip_address) DO UPDATE SET last_seen=NOW())
3. For newly discovered devices: create an alert with type="new_device", severity="high"
4. Return count of discovered devices

Confirm by running a network scan:
curl -X POST http://localhost:8080/api/v1/scan/network
Then: curl http://localhost:8080/api/v1/devices
Should show discovered devices.
```

---

## PROMPT 005 — Default Credential Scanner

```
You are continuing to build IronMesh. The network scanner is running. Now build the default credential testing module.

IMPORTANT SAFETY RULES — these must be implemented exactly as written:
- Maximum 50 credential pairs tested per device per scan
- Minimum 500ms delay between each attempt
- Stop immediately if a lockout response is detected (HTTP 429, or response body contains "locked", "disabled", "too many")
- Maximum 3 consecutive failures before moving to next credential pair
- Log every attempt with timestamp to audit trail (do not suppress)
- Never run credential tests in parallel against the same device

--- scanner/credentials.go ---

Create these types:
  type Credential struct {
      Username string
      Password string
  }

  type CredentialResult struct {
      Tested     int
      Found      bool
      Username   string
      Password   string
      Method     string  // "ssh", "http-basic", "telnet"
      LockedOut  bool
      AuditLog   []string
  }

Implement LoadCredentials(filepath string) ([]Credential, error):
- Read the file line by line
- Parse "username:password" format, skip blank lines and lines starting with #
- Return max 100 entries (truncate if file is longer)
- Return error if file not found

Implement TestSSHCreds(ip string, port int, creds []Credential, maxPairs int) CredentialResult:
- Use golang.org/x/crypto/ssh
- SSH config: timeout 5s, HostKeyCallback = InsecureIgnoreHostKey (note in comment: for production use known_hosts)
- For each credential up to maxPairs (max 50):
  - Log attempt: "[CRED-TEST] <timestamp> SSH <ip>:<port> user=<username>"
  - Attempt ssh.Dial with the credential
  - If success: close connection, set Found=true, record Username/Password, return immediately
  - If error contains "too many" or "locked": set LockedOut=true, return immediately
  - Sleep 500ms before next attempt
- Return result

Implement TestHTTPBasicCreds(ip string, port int, path string, creds []Credential, maxPairs int) CredentialResult:
- Use net/http with timeout 5s
- For each credential up to maxPairs:
  - Log attempt: "[CRED-TEST] <timestamp> HTTP-BASIC http://<ip>:<port><path> user=<username>"
  - Send GET request with Authorization: Basic <base64(user:pass)> header
  - If response is 200: set Found=true, return
  - If response is 429: set LockedOut=true, return
  - If response body contains "locked" or "disabled": set LockedOut=true, return
  - Sleep 500ms before next attempt

Implement TestTelnetCreds(ip string, port int, creds []Credential, maxPairs int) CredentialResult:
- Use net.DialTimeout("tcp", addr, 5s)
- Read initial banner (up to 1024 bytes, timeout 3s)
- For each credential up to maxPairs:
  - Log attempt: "[CRED-TEST] <timestamp> TELNET <ip>:<port> user=<username>"
  - Write username + newline, read response (timeout 3s)
  - Write password + newline, read response (timeout 3s)
  - If response does NOT contain "incorrect" or "failed" or "denied": set Found=true, return
  - Sleep 500ms before next attempt

--- Wire into scan pipeline ---
Update the scan goroutine in api/scans.go to run after port detection:
1. Load credentials from data/default-credentials.txt
2. If port 22 open: run TestSSHCreds(ip, 22, creds, 50)
3. If port 80 open: run TestHTTPBasicCreds(ip, 80, "/", creds, 50)
4. If port 443 open: run TestHTTPBasicCreds(ip, 443, "/", creds, 50) with TLS
5. If port 23 open: run TestTelnetCreds(ip, 23, creds, 20)

For each positive result (Found=true):
- Create vulnerability record: severity="critical", cvss_score=9.5, title="Default credentials active", description="Device accepted login with username: <username>", affected_component="authentication"
- Create alert record: alert_type="default_creds", severity="critical", title="Default credentials found on <ip>", metadata={"username": <username>, "method": <method>}
- Update device: add tag "default-creds" to tags array

For each LockedOut result:
- Log warning: "[WARNING] Credential lockout detected on <ip> - stopping credential tests for this device"
- Create alert: alert_type="lockout_detected", severity="medium", title="Account lockout triggered during scan of <ip>"

Confirm by setting up a test SSH server with default credentials and verifying the scanner finds it.
```

---

## PROMPT 006 — CISA KEV Integration

```
You are continuing to build IronMesh. Now integrate the CISA Known Exploited Vulnerabilities feed.

--- kev/updater.go ---

Create these types:
  type KEVEntry struct {
      CVEID             string    `json:"cveID"`
      VendorProject     string    `json:"vendorProject"`
      Product           string    `json:"product"`
      VulnerabilityName string    `json:"vulnerabilityName"`
      DateAdded         string    `json:"dateAdded"`
      ShortDescription  string    `json:"shortDescription"`
      RequiredAction    string    `json:"requiredAction"`
      DueDate           string    `json:"dueDate"`
  }

  type KEVCatalog struct {
      Title       string     `json:"title"`
      CatalogVersion string  `json:"catalogVersion"`
      DateReleased string    `json:"dateReleased"`
      Count        int       `json:"count"`
      Vulnerabilities []KEVEntry `json:"vulnerabilities"`
  }

Implement:

1. FetchKEV(cacheFilePath string) error
   - Download from: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
   - HTTP GET with timeout 30s and User-Agent "IronMesh-Security-Scanner/1.0"
   - Save raw response body to cacheFilePath
   - Log: "KEV catalog updated: <count> entries"
   - Return error if download fails

2. LoadKEV(cacheFilePath string) (*KEVCatalog, error)
   - Read and parse cacheFilePath as JSON
   - Return KEVCatalog
   - Return error with message "KEV cache not found - run FetchKEV first" if file missing

3. IsKEV(catalog *KEVCatalog, cveID string) bool
   - Case-insensitive check if cveID exists in catalog.Vulnerabilities
   - Use a map for O(1) lookup (build map once on first call, cache it)

4. GetKEVEntry(catalog *KEVCatalog, cveID string) *KEVEntry
   - Return the full KEVEntry for a CVE ID, or nil if not found

5. StartKEVUpdater(cacheFilePath string) *KEVCatalog
   - Fetch KEV on startup (call FetchKEV)
   - If fetch fails (no internet), try to load from cache
   - If cache also missing: log warning and return empty catalog (don't crash)
   - Start a background goroutine that calls FetchKEV every 24 hours
   - Return the initial catalog

--- Add KEV status endpoint ---
In api/router.go add: GET /api/v1/kev/status

In a new file api/kev.go implement the handler:
- Read the cache file modification time from data/cisa-kev.json
- Load the catalog and return count
- Response: {"last_updated": "<ISO timestamp>", "total_entries": <int>, "cache_file": "data/cisa-kev.json"}

--- Wire KEV into vulnerability creation ---
Add a CheckAndFlagKEV(db *sql.DB, catalog *KEVCatalog, vulnID string, cveID string) function that:
- Calls IsKEV(catalog, cveID)
- If true: UPDATE vulnerabilities SET is_kev=true, severity='critical' WHERE id=<vulnID>
- If true: create alert with alert_type="kev_match", severity="critical", title="CISA KEV match: <cveID>", description=<kev entry short description>

Call this function whenever a new vulnerability with a non-null cve_id is created anywhere in the codebase.

Update main.go to:
- Call kev.StartKEVUpdater("data/cisa-kev.json") at startup
- Pass the returned catalog to the router so handlers can use it

Confirm:
curl http://localhost:8080/api/v1/kev/status
Should return: {"last_updated": "<timestamp>", "total_entries": <number above 1000>, "cache_file": "data/cisa-kev.json"}
```

---

## PROMPT 007 — Risk Scoring Engine

```
You are continuing to build IronMesh. Now build the risk scoring engine.

--- risk/scorer.go ---

Create this struct exactly:
  type RiskFactors struct {
      HasDefaultCreds     bool
      HasTelnet           bool
      HasADB              bool
      HasModbus           bool
      HasUnauthRTSP       bool
      HasPlaintextMQTT    bool
      HasHTTPMgmt         bool
      HasWeakTLS          bool
      KnownCVECount       int
      KEVMatchCount       int
      FirmwareOutdated    bool
      HighEntropyFirmware bool
      DaysSinceLastScan   int
  }

Implement CalculateRiskScore(factors RiskFactors) float64:
  score := 0.0
  if factors.HasDefaultCreds     { score += 4.0 }
  if factors.HasTelnet           { score += 3.0 }
  if factors.HasADB              { score += 3.5 }
  if factors.HasModbus           { score += 2.5 }
  if factors.HasUnauthRTSP       { score += 2.0 }
  if factors.HasPlaintextMQTT    { score += 1.5 }
  if factors.HasHTTPMgmt         { score += 1.0 }
  if factors.HasWeakTLS          { score += 1.5 }
  score += math.Min(float64(factors.KnownCVECount)*0.5, 3.0)
  score += math.Min(float64(factors.KEVMatchCount)*2.0, 4.0)
  if factors.FirmwareOutdated    { score += 1.0 }
  if factors.HighEntropyFirmware { score += 2.0 }
  score += math.Min(float64(factors.DaysSinceLastScan)/30*0.1, 1.0)
  return math.Min(score, 10.0)

Implement SeverityFromScore(score float64) string:
  0.0 - 2.9: return "low"
  3.0 - 5.9: return "medium"
  6.0 - 7.9: return "high"
  8.0 - 10.0: return "critical"

--- risk/updater.go ---

Implement BuildRiskFactors(db *sql.DB, deviceID string) (RiskFactors, error):
- Query vulnerabilities for this device to check which protocol findings exist:
  SELECT title FROM vulnerabilities WHERE device_id=$1 AND is_resolved=FALSE
- Build flags by checking titles against these strings:
  "Telnet" in title → HasTelnet = true
  "ADB" or "Android Debug" in title → HasADB = true
  "Modbus" in title → HasModbus = true
  "RTSP" in title → HasUnauthRTSP = true
  "MQTT" in title → HasPlaintextMQTT = true
  "HTTP" in title → HasHTTPMgmt = true
  "Default credentials" in title → HasDefaultCreds = true
  "TLS" in title → HasWeakTLS = true
- Query: SELECT COUNT(*) FROM vulnerabilities WHERE device_id=$1 AND cve_id IS NOT NULL AND is_resolved=FALSE → KnownCVECount
- Query: SELECT COUNT(*) FROM vulnerabilities WHERE device_id=$1 AND is_kev=TRUE AND is_resolved=FALSE → KEVMatchCount
- Query: SELECT entropy_score FROM firmware WHERE device_id=$1 ORDER BY analyzed_at DESC LIMIT 1 → HighEntropyFirmware = (score > 7.2)
- Query: SELECT started_at FROM scans WHERE device_id=$1 ORDER BY started_at DESC LIMIT 1 → DaysSinceLastScan

Implement UpdateDeviceRiskScore(db *sql.DB, deviceID string) error:
- Call BuildRiskFactors(db, deviceID)
- Call CalculateRiskScore(factors)
- UPDATE devices SET risk_score=$1 WHERE id=$2
- Log: "Risk score updated for device <id>: <old_score> → <new_score>"
- Return error if anything fails

Implement GetRiskBreakdown(db *sql.DB, deviceID string) map[string]interface{}:
- Call BuildRiskFactors
- Call CalculateRiskScore
- Return a map with keys: total_score, severity, factors (the RiskFactors struct), score_breakdown (map of each factor name to its point contribution)

--- Wire into scan completion ---
At the end of every scan goroutine in api/scans.go, after all findings are saved, call:
  risk.UpdateDeviceRiskScore(db, deviceID)

--- Wire risk breakdown endpoint ---
In api/devices.go implement GET /devices/:id/risk-breakdown:
  Call risk.GetRiskBreakdown(db, deviceID)
  Return the result as the data payload

Confirm:
1. Run a scan on a device
2. curl http://localhost:8080/api/v1/devices/<id>/risk-breakdown
Should return a breakdown showing which factors contributed to the score.
```

---

## PROMPT 008 — Alerting Engine

```
You are continuing to build IronMesh. Now build the full alerting system.

--- alerts/engine.go ---

Create this type:
  type AlertRequest struct {
      DeviceID    string
      AlertType   string
      Severity    string
      Title       string
      Description string
      Metadata    map[string]interface{}
  }

Implement CreateAlert(db *sql.DB, req AlertRequest) error:
1. Deduplication check: query alerts table for any row where:
   device_id = req.DeviceID AND alert_type = req.AlertType AND is_acknowledged = FALSE AND triggered_at > NOW() - INTERVAL '24 hours'
   If a row exists: log "Alert deduplicated: <type> for device <id>" and return nil (not an error)
2. If no duplicate: INSERT INTO alerts (device_id, severity, alert_type, title, description, metadata) VALUES (...)
3. Log to stdout: "[ALERT] <severity> | <alert_type> | <title> | device: <device_id>"
4. Return any insert error

Implement StartAlertMonitor(db *sql.DB):
- Run as a background goroutine (call with go StartAlertMonitor(db))
- Loop every 60 seconds using time.NewTicker(60 * time.Second)

Inside the loop:

Check 1 — Offline devices:
  SELECT id, ip_address FROM devices WHERE is_active=TRUE AND last_seen < NOW() - INTERVAL '30 minutes'
  For each row: call CreateAlert with alert_type="device_offline", severity="medium", title="Device offline: <ip>"

Check 2 — Firmware overdue for review:
  SELECT device_id FROM firmware WHERE analyzed_at < NOW() - INTERVAL '90 days' OR analyzed_at IS NULL
  For each row: call CreateAlert with alert_type="firmware_review_due", severity="low", title="Firmware analysis overdue"

Check 3 — Unresolved critical vulns older than 7 days:
  SELECT DISTINCT device_id FROM vulnerabilities WHERE severity='critical' AND is_resolved=FALSE AND discovered_at < NOW() - INTERVAL '7 days'
  For each row: call CreateAlert with alert_type="critical_vuln_unresolved", severity="high", title="Critical vulnerability unresolved for 7+ days"

All three checks should catch and log errors without crashing the goroutine (use recover() or careful error handling).

--- Alert type constants ---
Create alerts/types.go with constants:
  const (
      AlertDefaultCreds       = "default_creds"
      AlertKEVMatch           = "kev_match"
      AlertTelnetOpen         = "telnet_open"
      AlertADBExposed         = "adb_exposed"
      AlertPlaintextMQTT      = "plaintext_mqtt"
      AlertUnauthRTSP         = "unauth_rtsp"
      AlertNewDevice          = "new_device"
      AlertDeviceOffline      = "device_offline"
      AlertFirmwareEntropy    = "firmware_entropy"
      AlertWeakTLS            = "tls_weak"
      AlertCertExpiring       = "cert_expiring"
      AlertLockedOut          = "lockout_detected"
      AlertCriticalUnresolved = "critical_vuln_unresolved"
      AlertFirmwareReview     = "firmware_review_due"
  )

--- Update all scanner integrations to use CreateAlert ---
Replace any direct alert INSERT statements in scanner/protocols.go, scanner/credentials.go, and api/scans.go with calls to alerts.CreateAlert(db, AlertRequest{...}) using the correct constants from alerts/types.go.

--- Update main.go ---
After database setup and before starting the HTTP server, call:
  go alerts.StartAlertMonitor(db)

Confirm:
1. Set a device's last_seen to 2 hours ago manually in the database:
   UPDATE devices SET last_seen = NOW() - INTERVAL '2 hours' WHERE ip_address = '192.168.1.1';
2. Wait 60 seconds for the monitor to run
3. curl http://localhost:8080/api/v1/alerts
Should show a device_offline alert for that device.
4. Run the same update again. Wait 60 more seconds. The alert count should NOT increase (deduplication).
```

---

## PROMPT 009 — Firmware Analyzer (Python Microservice)

```
You are continuing to build IronMesh. Now build the Python firmware analysis microservice.

--- firmware-analyzer/requirements.txt ---
fastapi==0.111.0
uvicorn==0.29.0
requests==2.31.0
psycopg2-binary==2.9.9
python-multipart==0.0.9

Note: binwalk will be installed via apt in Dockerfile, not pip.

--- firmware-analyzer/entropy.py ---
Implement exactly:

import math
from collections import Counter
from pathlib import Path

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

def analyze_file_entropy(filepath: str) -> dict:
    path = Path(filepath)
    if not path.exists():
        return {"error": f"File not found: {filepath}"}
    with open(filepath, 'rb') as f:
        data = f.read()
    entropy = shannon_entropy(data)
    file_size = len(data)
    verdict = "normal"
    if entropy > 7.2:
        verdict = "encrypted_or_packed"
    elif entropy > 6.5:
        verdict = "compressed_or_mixed"
    return {
        "entropy_score": round(entropy, 4),
        "file_size_bytes": file_size,
        "verdict": verdict,
        "suspicious": entropy > 7.2,
        "threshold_used": 7.2
    }

--- firmware-analyzer/binwalk_runner.py ---

SUSPICIOUS_PATTERNS = [
    r'/bin/sh', r'/bin/bash', r'/bin/ash',
    r'wget http', r'curl http', r'chmod \+x',
    r'telnetd', r'dropbear',
    r'password=\w+', r'passwd=\w+', r'secret=\w+',
    r'\.onion',
    r'nc -l', r'netcat',
    r'base64 -d',
    r'rm -rf /',
    r'iptables -F',
]

import re
import subprocess
import os
from pathlib import Path

def extract_strings(filepath: str, min_length: int = 8) -> list[str]:
    """Run strings command on the file and return all strings above min_length."""
    try:
        result = subprocess.run(
            ['strings', '-n', str(min_length), filepath],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout.splitlines()
    except Exception as e:
        return [f"strings extraction failed: {str(e)}"]

def find_suspicious_strings(filepath: str) -> list[str]:
    """Return strings from the file that match suspicious patterns."""
    all_strings = extract_strings(filepath)
    findings = []
    for pattern in SUSPICIOUS_PATTERNS:
        regex = re.compile(pattern, re.IGNORECASE)
        for s in all_strings:
            if regex.search(s) and s not in findings:
                findings.append(s.strip())
    return findings[:50]  # cap at 50 findings

def run_binwalk(filepath: str) -> dict:
    """Run binwalk signature scan and return parsed output."""
    try:
        result = subprocess.run(
            ['binwalk', '--signature', filepath],
            capture_output=True, text=True, timeout=60
        )
        return {
            "output": result.stdout,
            "signatures_found": [
                line.strip()
                for line in result.stdout.splitlines()
                if line.strip() and not line.startswith('DECIMAL')
                and not line.startswith('-')
            ]
        }
    except FileNotFoundError:
        return {"output": "binwalk not installed", "signatures_found": []}
    except Exception as e:
        return {"output": str(e), "signatures_found": []}

--- firmware-analyzer/cve_lookup.py ---

import requests
import time
import os

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def lookup_cve(vendor: str, version: str, api_key: str = None) -> list[dict]:
    """Query NVD for CVEs matching vendor and firmware version."""
    keyword = f"{vendor} {version}".strip()
    if not keyword or keyword == " ":
        return []
    
    headers = {"User-Agent": "IronMesh-Security-Scanner/1.0"}
    if api_key:
        headers["apiKey"] = api_key
    
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 20,
    }
    
    # Rate limiting: 6s without key, 0.6s with key
    sleep_time = 0.6 if api_key else 6.0
    time.sleep(sleep_time)
    
    try:
        resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return [{"error": str(e)}]
    
    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        
        # Get CVSS score (try v3.1 first, then v2)
        cvss = None
        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metrics:
            cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
        
        if cvss is None or cvss < 4.0:
            continue  # Skip low-severity findings
        
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        
        results.append({
            "cve_id": cve_id,
            "cvss_score": cvss,
            "description": desc[:500],
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        })
    
    return results

--- firmware-analyzer/main.py ---

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import psycopg2
import os
import json
from datetime import datetime
from entropy import analyze_file_entropy
from binwalk_runner import find_suspicious_strings, run_binwalk
from cve_lookup import lookup_cve

app = FastAPI(title="IronMesh Firmware Analyzer")

DB_URL = os.environ.get("DATABASE_URL", "")
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

def get_db():
    return psycopg2.connect(DB_URL)

class AnalyzeRequest(BaseModel):
    firmware_id: str
    filepath: str
    vendor: str = ""
    version: str = ""

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/analyze")
def analyze_firmware(req: AnalyzeRequest):
    report = {}
    
    # Step 1: Entropy analysis
    entropy_result = analyze_file_entropy(req.filepath)
    report["entropy"] = entropy_result
    
    # Step 2: String extraction
    suspicious_strings = find_suspicious_strings(req.filepath)
    report["suspicious_strings"] = suspicious_strings
    report["suspicious_string_count"] = len(suspicious_strings)
    
    # Step 3: Binwalk signature scan
    binwalk_result = run_binwalk(req.filepath)
    report["binwalk"] = binwalk_result
    
    # Step 4: CVE lookup
    cve_results = []
    if req.vendor or req.version:
        cve_results = lookup_cve(req.vendor, req.version, NVD_API_KEY)
    report["cve_matches"] = cve_results
    
    # Step 5: Update database
    cve_ids = [c["cve_id"] for c in cve_results if "cve_id" in c]
    entropy_score = entropy_result.get("entropy_score", 0)
    has_backdoor = len(suspicious_strings) > 0
    
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            UPDATE firmware SET
                entropy_score = %s,
                has_backdoor_indicators = %s,
                strings_of_interest = %s,
                cve_matches = %s,
                analyzed_at = %s,
                analysis_status = 'complete',
                analysis_report = %s
            WHERE id = %s
        """, (
            entropy_score,
            has_backdoor,
            suspicious_strings,
            cve_ids,
            datetime.utcnow(),
            json.dumps(report),
            req.firmware_id
        ))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        report["db_error"] = str(e)
    
    return {
        "firmware_id": req.firmware_id,
        "status": "complete",
        "report": report
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)

--- firmware-analyzer/Dockerfile ---
FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    binwalk \
    nmap \
    binutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8001
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]

--- Wire into Go backend ---
In api/firmware.go, update POST /firmware/:id/analyze to:
1. Get the firmware record from the database
2. Make an HTTP POST to http://firmware-analyzer:8001/analyze with JSON body: {"firmware_id": id, "filepath": firmware.FilePath, "vendor": firmware.Vendor, "version": firmware.Version}
3. Do this in a goroutine (non-blocking)
4. After analysis completes, if entropy_score > 7.2: call alerts.CreateAlert with alert_type="firmware_entropy"

Confirm:
docker compose up firmware-analyzer
curl -X POST http://localhost:8001/analyze -H "Content-Type: application/json" -d '{"firmware_id":"test-123","filepath":"/etc/passwd","vendor":"test","version":"1.0"}'
Should return a JSON report with entropy_score and suspicious_strings.
```

---

## PROMPT 010 — React Frontend

```
You are continuing to build IronMesh. The backend API is complete. Now build the React frontend.

Use: React 18 + TypeScript + Tailwind CSS + recharts + axios + react-router-dom v6.

--- frontend/src/api/client.ts ---
Create an axios instance:
- baseURL from REACT_APP_API_URL env var, fallback to http://localhost:8080/api/v1
- default headers: Content-Type: application/json
- response interceptor: if response.data.error is non-null, throw new Error(response.data.error)
- export typed helper functions: getStats(), getDevices(params?), getDevice(id), triggerScan(deviceId), triggerNetworkScan(), getVulnerabilities(params?), resolveVuln(id), getAlerts(params?), ackAlert(id), getKEVStatus()

--- frontend/src/pages/Dashboard.tsx ---
Layout: top bar with IronMesh logo + "IoT Security Platform" subtitle, right side shows KEV status badge.

Four metric cards in a row:
- Total Devices (icon: server)
- Open Vulnerabilities (icon: bug, show critical count in red)
- Unacknowledged Alerts (icon: bell)
- Avg Risk Score (number colored by severity: green/blue/amber/red)

Below cards: two columns:
- Left: Recent Alerts (AlertFeed component, last 10)
- Right: Risk Distribution (recharts BarChart showing count of low/medium/high/critical devices)

Auto-refresh every 30 seconds using setInterval in useEffect. Show last-refreshed timestamp in top bar.

--- frontend/src/pages/Devices.tsx ---
Full-width table with columns: IP Address, Hostname, Vendor, Device Type, Risk Score, Last Seen, Actions.

Risk Score column: colored badge.
  0-2.9: green badge with text "Low"
  3-5.9: blue badge with text "Medium"  
  6-7.9: amber badge with text "High"
  8-10: red badge with text "Critical <score>"

Actions column: "Scan" button. On click: calls triggerScan(device.id), shows spinner, disables button while scan is running, re-enables after 3 seconds.

Top of page: search input (filters table by IP/hostname client-side), device type dropdown filter, risk level dropdown filter.

Click on any table row (except the Scan button): navigate to /devices/<id>

--- frontend/src/pages/DeviceDetail.tsx ---
Get device ID from URL params. Fetch device detail on mount.

Top section: device info card showing IP, MAC, hostname, vendor, device type, first seen, last seen, current risk score (large colored number).

Risk breakdown section: fetch /devices/:id/risk-breakdown. Show each factor as a row with icon, label, and point contribution. Only show factors that are active (non-zero).

Three tabs: Vulnerabilities | Scan History | Firmware

Vulnerabilities tab: table of vulns for this device. Columns: Severity badge, CVE ID (link to nvd.nist.gov if exists), Title, CVSS Score, KEV badge (red "KEV" pill if is_kev=true), Discovered, Action (Resolve button).

Scan History tab: list of scans with start time, status badge (running=blue, complete=green, failed=red), duration, open ports count.

Firmware tab: firmware records with entropy score shown as a colored meter (green <6.5, amber 6.5-7.2, red >7.2). Show analysis status and link to trigger analysis.

--- frontend/src/pages/Vulnerabilities.tsx ---
Full vulnerability list across all devices.

Filters at top: Severity select, KEV Only toggle, Unresolved Only toggle (default: true), search by CVE ID.

Table columns: Severity badge, CVE ID (external link), Device IP, Title, CVSS, KEV badge, Discovered, Status (resolved/open), Resolve button.

Sort by CVSS score descending by default.

--- frontend/src/components/AlertFeed.tsx ---
Props: { limit?: number, showDevice?: boolean }

Each alert row:
- Severity icon (critical=red X, high=amber triangle, medium=blue info, low=gray info)
- Alert title
- Device IP (if showDevice=true)
- Relative time ("3 min ago", "2h ago") — recompute every minute
- Acknowledge button (gray X icon) — calls ackAlert(id), removes from list on success

New alerts (triggered_at within last 60 seconds) have a subtle left border accent animation.

--- frontend/src/components/RiskScore.tsx ---
Props: { score: number, size?: 'sm' | 'md' | 'lg' }

Renders a circular SVG ring:
- Ring fills proportionally (score/10 of circumference)
- Color: green (0-2.9), blue (3-5.9), amber (6-7.9), red (8-10)
- Score number centered inside ring
- Severity label below ring

--- frontend/src/App.tsx ---
Set up react-router-dom v6 routes:
  / → Dashboard
  /devices → Devices
  /devices/:id → DeviceDetail
  /vulnerabilities → Vulnerabilities

Left sidebar navigation with links and icons. Active route highlighted.

--- Tailwind CSS ---
Configure tailwind.config.js to scan src/**/*.tsx.
Color classes to use for severity:
  critical: red-600 bg-red-50 border-red-200
  high: amber-600 bg-amber-50 border-amber-200
  medium: blue-600 bg-blue-50 border-blue-200
  low: green-600 bg-green-50 border-green-200

--- frontend/Dockerfile ---
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80

Create nginx.conf that:
- Serves the React build on port 80
- Proxies /api/ requests to http://backend:8080/api/ (so no CORS issues in production)
- Handles client-side routing (try_files $uri $uri/ /index.html)

Confirm:
npm start
Open http://localhost:3000
All 4 pages must render without console errors.
Dashboard must show real data from the API.
Scanning a device from the Devices page must create a scan record visible in DeviceDetail.
```

---

## PROMPT 011 — Docker Compose & Final Wiring

```
You are finishing the IronMesh build. Wire everything together with Docker Compose and verify the full system works end-to-end.

--- docker-compose.yml ---
Create this file exactly:

version: '3.9'

services:
  postgres:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: ironmesh
      POSTGRES_USER: ironmesh
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ironmesh"]
      interval: 5s
      timeout: 5s
      retries: 10

  backend:
    build: ./backend
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      DATABASE_URL: postgres://ironmesh:${DB_PASSWORD}@postgres:5432/ironmesh?sslmode=disable
      PORT: 8080
      NETWORK_CIDR: ${NETWORK_CIDR:-192.168.1.0/24}
      NVD_API_KEY: ${NVD_API_KEY:-}
      FIRMWARE_ANALYZER_URL: http://firmware-analyzer:8001
    ports:
      - "8080:8080"
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - ./data:/app/data

  firmware-analyzer:
    build: ./firmware-analyzer
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      DATABASE_URL: postgres://ironmesh:${DB_PASSWORD}@postgres:5432/ironmesh?sslmode=disable
      NVD_API_KEY: ${NVD_API_KEY:-}
    volumes:
      - firmware_data:/firmware
    ports:
      - "8001:8001"

  frontend:
    build: ./frontend
    restart: unless-stopped
    depends_on:
      - backend
    ports:
      - "3000:80"
    environment:
      REACT_APP_API_URL: /api/v1

volumes:
  postgres_data:
  firmware_data:

--- backend/Dockerfile ---
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache nmap

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o ironmesh .

FROM alpine:3.19
RUN apk add --no-cache nmap ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/ironmesh .
COPY --from=builder /app/data ./data

EXPOSE 8080
CMD ["./ironmesh"]

--- Verify network_mode: host for nmap ---
The backend service must use network_mode: host so nmap can see the local network.
Note: network_mode: host overrides the ports directive on Linux. The port is still accessible at :8080 on the host.
On Mac/Windows (Docker Desktop): network_mode: host behaves differently. Add a note in README.md that full scanner functionality requires Linux host or a dedicated VM.

--- Final integration checks ---
Make sure these connections all work:
1. Go backend → PostgreSQL: DATABASE_URL env var
2. Go backend → firmware-analyzer: FIRMWARE_ANALYZER_URL env var, used in api/firmware.go when triggering analysis
3. firmware-analyzer → PostgreSQL: DATABASE_URL env var, used in main.py to update firmware records
4. Frontend nginx → backend: proxy_pass in nginx.conf

--- Create a Makefile in project root ---
.PHONY: up down logs scan stats reset

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f

scan:
	curl -s -X POST http://localhost:8080/api/v1/scan/network | jq .

stats:
	curl -s http://localhost:8080/api/v1/stats | jq .

reset:
	docker compose down -v
	docker compose up -d --build

Confirm full system:
1. make up
2. Wait 30 seconds for all services to start
3. make stats → should return JSON with device counts
4. make scan → should return {"data": {"discovered": <n>}}
5. Open http://localhost:3000 → dashboard loads with real data
6. Click Scan on a device → scan completes and risk score updates
7. curl http://localhost:8080/api/v1/alerts → shows new_device alerts for discovered devices

If all 7 checks pass, the system is fully operational.
```

---

## PROMPT 012 — README & Threat Model

```
You are writing the documentation for IronMesh that will make people on GitHub star it, share it, and hire the person who built it.

--- README.md ---

Write a README with these sections in order:

1. A one-line tagline: "Open-source IoT security platform. Find vulnerable devices before attackers do."

2. A badges row (use shields.io):
   - License: MIT
   - Go version: 1.22
   - Docker: required
   - Stars: (leave as placeholder)

3. A "What this does" section (3-4 sentences): explain it finds IoT devices on your network, scans them for real CVEs, tests for default credentials, analyzes firmware for malware, and scores risk 0-10. Lead with the problem (820K IoT attacks per day), not the technology.

4. A "Setup in 5 minutes" section — exact commands:
   git clone https://github.com/yourusername/ironmesh
   cd ironmesh
   cp .env.example .env
   # Edit .env: set your network CIDR (e.g. 192.168.1.0/24)
   docker compose up -d
   open http://localhost:3000

5. A "What it detects" section — a table with 3 columns: Threat | Real-world example | How IronMesh catches it:
   - Default credentials | Mirai botnet (820K attacks/day) | Tests top-100 credential pairs per device, scores 9.5 if found
   - Telnet exposure | Aisuru botnet (20+ Tbps DDoS) | Detects open port 23, creates Critical alert
   - CISA KEV matches | AVTECH CVE-2024-7029 | Cross-references every CVE against CISA's active exploit list
   - ADB exposure | BadBox 2.0 (10M pre-infected devices) | Detects port 5555 ADB banner, flags as supply chain risk
   - Industrial protocols | April 2026 ICS advisories | Fingerprints Modbus (502) and BACnet (47808), scores Critical
   - Firmware malware | Supply chain implants | Shannon entropy analysis: score >7.2 = encrypted/packed payload
   - Unencrypted MQTT | 24% of IoT apps have TLS issues | Detects port 1883 without TLS, flags cleartext broker
   - Unauthenticated RTSP | Nation-state camera surveillance | RTSP OPTIONS without auth challenge = exposed stream

6. A "Architecture" section with an ASCII diagram showing: Frontend → Go API → [Scanner | Firmware Analyzer | Risk Scorer | Alerting] → PostgreSQL

7. A "Requirements" section:
   - Docker and Docker Compose
   - Linux host recommended for full nmap functionality (or a Linux VM on Mac/Windows)
   - 2GB RAM, 10GB disk
   - Optional: NVD API key (free at nvd.nist.gov) for faster CVE lookups

8. A "Configuration" section documenting all .env variables with descriptions and examples

9. A "Adding new checks" section with a 5-step guide: (1) add vulnerability check function in scanner/, (2) call alerts.CreateAlert with appropriate type constant, (3) add risk factor to RiskFactors struct, (4) update CalculateRiskScore, (5) open a PR

10. A "Responsible use" section: "IronMesh performs active network scanning and credential testing. Only use it on networks you own or have explicit written permission to test. Unauthorized scanning may be illegal in your jurisdiction."

11. License: MIT

--- THREAT_MODEL.md ---

Write a threat model document with these sections:

1. Scope: what IronMesh protects against (network-visible IoT devices, their credentials, firmware, exposed protocols)

2. Out of scope: physical device access, encrypted traffic interception, zero-day discovery, lateral movement after compromise

3. For each of these 6 threats, write: Attack surface | Attacker capability required | IronMesh detection | Remediation recommendation
   - Default credential attacks
   - Botnet recruitment via Telnet/ADB
   - Supply chain firmware compromise
   - OT/ICS protocol exploitation  
   - Insecure communication interception
   - CISA KEV exploitation

4. Limitations:
   - Credential testing is semi-active (sends login attempts) — may trigger security tools
   - Firmware analysis requires the firmware file to be present locally
   - Entropy analysis has a false positive rate — compressed legitimate firmware may score high
   - Network scanning requires nmap and raw socket access — must run as privileged container
   - IronMesh does not monitor encrypted traffic (no MitM)

5. Safe scanning guidelines: rate limits, delay between attempts, lockout detection, audit logging

--- CONTRIBUTING.md ---

Write a contribution guide with:
1. How to add a new protocol scanner (with a code template showing the ProtocolFinding struct usage)
2. How to add new default credentials (format, where to add, how to test)
3. How to add a new alert type (add constant to alerts/types.go, call CreateAlert, document the metadata schema)
4. How to run tests locally
5. PR checklist: does it add a new real threat detection? Does it include a test? Does it update the README "What it detects" table?

Confirm when all three documentation files are complete and the README reads clearly to someone who has never seen the project before.
```

---

## Sequence summary

| Order | What it builds | Estimated time |
|---|---|---|
| 001 | Project scaffold + deps | 10 min |
| 002 | Database + migrations | 15 min |
| 003 | Go REST API | 30 min |
| 004 | Network discovery scanner | 45 min |
| 005 | Default credential scanner | 30 min |
| 006 | CISA KEV integration | 20 min |
| 007 | Risk scoring engine | 20 min |
| 008 | Alerting engine | 25 min |
| 009 | Python firmware analyzer | 40 min |
| 010 | React frontend | 60 min |
| 011 | Docker Compose + final wiring | 20 min |
| 012 | README + Threat Model | 20 min |

**Total estimated build time with an agent: 5-6 hours**

---

*Each prompt is self-contained. If an agent fails on a step, paste the error back in with "Fix this and continue." Do not skip orders — each one assumes the previous is complete.*