# Seagles Production Upgrade Plan

To elevate Seagles from a highly-functional Minimum Viable Product (MVP) to a 10/10, enterprise-grade, production-ready security platform, the following architectural and security enhancements must be implemented.

---

## 1. Authentication & Authorization (Zero Trust)
**The Vulnerability:** 
Currently, the React frontend and Go API have no authentication layer. Anyone with network routing access to port 3000 or 8080 can trigger active scans, view network topologies, and access sensitive vulnerability data.
**The Implementation Plan:**
*   **JWT Auth:** Implement JSON Web Token (JWT) based authentication in the Go backend (`/api/v1/auth/login`).
*   **Role-Based Access Control (RBAC):** Create distinct user roles:
    *   `Admin`: Can trigger network scans, resolve vulnerabilities, and manage credentials.
    *   `Viewer`: Read-only access to dashboards and reports.
*   **Frontend Routing:** Wrap React routes in a protected component that enforces session validity and redirects to a login page.

## 2. Scanner Safelists & Rules of Engagement
**The Vulnerability:**
Active network scanning (Nmap, credential brute-forcing, protocol probing) can inadvertently crash fragile legacy IoT systems, medical devices (IoMT), or Industrial Control Systems (ICS).
**The Implementation Plan:**
*   **Exclusion Lists:** Add a database table for `safelists` to explicitly exclude specific IP addresses, MAC addresses, or CIDR ranges from active scans.
*   **Scan Profiles:** Allow users to define "gentle" vs. "aggressive" scan profiles (e.g., skip credential testing on fragile PLCs).
*   **Dynamic Scoping:** Move the `NETWORK_CIDR` environment variable into the database so administrators can manage scan scopes directly from the UI.

## 3. Passive Network Monitoring (PCAP)
**The Vulnerability:**
Seagles relies entirely on *active* scheduled scanning. If an IoT device is compromised and begins beaconing to a Command and Control (C2) server between scheduled scans, the activity will go unnoticed until the next scan cycle.
**The Implementation Plan:**
*   **Traffic Mirroring:** Implement a new Go module using `google/gopacket` to passively monitor network interfaces (via SPAN/mirror ports).
*   **Behavioral Detection:** Silently analyze traffic 24/7 to catch rogue DHCP servers, DNS requests to known malware domains, or credentials being transmitted in cleartext.

## 4. Enterprise Integrations (SIEM & ChatOps)
**The Vulnerability:**
Alerts currently reside in the PostgreSQL database and are only visible when a user actively checks the React dashboard, leading to delayed incident response.
**The Implementation Plan:**
*   **Webhook Engine:** Build an outbound webhook dispatcher in `alerts/engine.go`.
*   **ChatOps:** Push critical and high-severity alerts immediately to Slack or Microsoft Teams channels.
*   **SIEM Forwarding:** Export alert and vulnerability data in Common Event Format (CEF) or Syslog to integrate with enterprise SIEMs (Splunk, Datadog, Elastic Security).

## 5. Firmware Upload & Management Pipeline
**The Vulnerability:**
The Python firmware microservice is fully functional, but the Go backend lacks an API endpoint for users to securely upload firmware binaries for analysis.
**The Implementation Plan:**
*   **Object Storage:** Integrate an S3-compatible storage backend (e.g., MinIO or AWS S3) for secure storage of firmware binaries.
*   **Upload API:** Create a `POST /firmware/upload` endpoint in the Go API that handles multipart form data, streams the file to S3, and triggers the Python analyzer using a pre-signed download URL.

## 6. Expanded Vulnerability Context (EPSS)
**The Vulnerability:**
Seagles flags vulnerabilities based on CVSS scores and CISA KEV matches, but lacks context on the actual probability of a vulnerability being exploited in the wild.
**The Implementation Plan:**
*   **EPSS Integration:** Integrate the Exploit Prediction Scoring System (EPSS) API alongside the NVD CVE lookups.
*   **Risk Context:** Use EPSS scores to help security teams prioritize patching (e.g., a CVSS 9.8 vulnerability with an EPSS score of 0.01% may be a lower priority than a CVSS 7.5 with an EPSS score of 85%).

## 7. Automated Testing & CI/CD
**The Vulnerability:**
While the codebase compiles cleanly, the absence of automated tests makes future refactoring and feature additions risky.
**The Implementation Plan:**
*   **Unit Testing:** Write comprehensive Go tests (`go test`) for the scanner, risk, and alert modules, and Python tests (`pytest`) for the firmware analyzer.
*   **E2E Testing:** Implement end-to-end UI tests using Cypress or Playwright to verify the frontend workflows.
*   **CI Pipeline:** Setup GitHub Actions to run linters (`golangci-lint`, `eslint`), execute the test suite, and build the Docker containers on every pull request.
