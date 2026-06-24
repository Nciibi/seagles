# Contributing to IronMesh

Thank you for your interest in making IoT security more accessible. Here's how to contribute.

---

## 1. Adding a New Protocol Scanner

Create a detection function in `backend/scanner/protocols.go`:

```go
func detectMyProtocol(ip string, port int) *ProtocolFinding {
    addr := fmt.Sprintf("%s:%d", ip, port)
    conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
    if err != nil {
        return nil
    }
    defer conn.Close()

    // Send protocol-specific probe
    conn.Write([]byte{...})

    // Read and analyze response
    buf := make([]byte, 256)
    n, _ := conn.Read(buf)

    if isVulnerable(buf[:n]) {
        return &ProtocolFinding{
            Protocol:    "MyProtocol",
            Port:        port,
            Risk:        "high",  // "critical", "high", "medium", "low"
            Description: "Description of the security risk",
            Evidence:    "What was detected",
        }
    }
    return nil
}
```

Then add the port check in `DetectProtocols()`:
```go
if portSet[YOUR_PORT] {
    if f := detectMyProtocol(ip, YOUR_PORT); f != nil {
        findings = append(findings, *f)
    }
}
```

## 2. Adding New Default Credentials

Edit `data/default-credentials.txt`. Format: `username:password`, one per line.

```
# My vendor defaults
myvendor_admin:myvendor_pass
```

Rules:
- Use `(blank)` for empty passwords: `admin:(blank)`
- Lines starting with `#` are comments
- Maximum 100 entries (file is truncated after that)
- Source credentials from **publicly documented** defaults only (vendor manuals, SecLists)

## 3. Adding a New Alert Type

### Step 1: Add the constant to `backend/alerts/engine.go`

```go
const (
    AlertMyNewType = "my_new_type"
)
```

### Step 2: Create the alert where appropriate

```go
alerts.CreateAlert(db, alerts.AlertRequest{
    DeviceID:    deviceID,
    AlertType:   alerts.AlertMyNewType,
    Severity:    "high",
    Title:       "Descriptive alert title",
    Description: "What happened and why it matters",
    Metadata:    json.RawMessage(`{"key": "value"}`),
})
```

### Step 3: Document the metadata schema

Alert metadata should be a JSON object documenting what triggered the alert. Common fields:
- `port`: the port number involved
- `protocol`: the protocol detected
- `username`: credential found (if applicable)
- `evidence`: raw evidence string

## 4. Adding a Risk Factor

### Step 1: Add to `RiskFactors` struct in `backend/risk/scorer.go`

```go
type RiskFactors struct {
    // ... existing fields ...
    HasMyNewFactor bool `json:"has_my_new_factor"`
}
```

### Step 2: Add scoring in `CalculateRiskScore()`

```go
if factors.HasMyNewFactor {
    score += 2.0  // Choose appropriate weight
}
```

### Step 3: Add detection in `BuildRiskFactors()`

```go
if strings.Contains(titleLower, "my detection keyword") {
    factors.HasMyNewFactor = true
}
```

### Step 4: Add to `ScoreBreakdown()`

```go
if factors.HasMyNewFactor {
    breakdown["my_new_factor"] = 2.0
}
```

## 5. Running Locally

```bash
# Start PostgreSQL
docker run -d -e POSTGRES_PASSWORD=test -e POSTGRES_DB=ironmesh -p 5432:5432 postgres:16-alpine

# Set environment
export DATABASE_URL="postgres://postgres:test@localhost:5432/ironmesh?sslmode=disable"

# Run backend
cd backend && go run main.go

# Run frontend (separate terminal)
cd frontend && npm install && npm run dev
```

## 6. PR Checklist

Before submitting a pull request:

- [ ] Does it add a **real threat detection**? (Not hypothetical)
- [ ] Is the detection **safe**? (Rate limited, non-destructive)
- [ ] Does it include **audit logging**?
- [ ] Does it create appropriate **alerts** with deduplication?
- [ ] Does it update the **risk scoring** if applicable?
- [ ] Does it update the README **"What it detects"** table?
- [ ] Does it follow the existing **code patterns**?

---

*Questions? Open an issue. We're here to help.*
