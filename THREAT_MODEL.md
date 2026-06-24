# IronMesh — Threat Model

## 1. Scope

IronMesh protects against threats that are **visible from the network layer** on IoT and connected devices:

- **Discovery**: Network-attached IoT devices (routers, cameras, sensors, PLCs, smart appliances)
- **Authentication**: Default and weak credentials on SSH, HTTP, and Telnet services
- **Protocols**: Dangerous protocol exposure (Telnet, Modbus, plaintext MQTT, unauthenticated RTSP, ADB)
- **Firmware**: Malicious or compromised firmware via entropy analysis and CVE matching
- **Encryption**: Weak or absent TLS configurations
- **Known Exploits**: Cross-referencing against CISA Known Exploited Vulnerabilities (KEV) catalog

## 2. Out of Scope

IronMesh **does not** protect against:

- **Physical device access** — tampering, hardware implants, JTAG/UART extraction
- **Encrypted traffic interception** — IronMesh does not perform MitM or decrypt traffic
- **Zero-day discovery** — IronMesh matches against known CVEs, it does not discover new ones
- **Lateral movement post-compromise** — IronMesh detects entry points, not attacker behavior inside the network
- **Application-layer vulnerabilities** — SQL injection, XSS, and similar web app flaws on device interfaces
- **Supply chain verification** — IronMesh flags suspicious firmware entropy but cannot verify provenance

## 3. Threat Analysis

### 3.1 Default Credential Attacks

| Aspect | Detail |
|---|---|
| **Attack Surface** | SSH (22), HTTP (80/443), Telnet (23) management interfaces |
| **Attacker Capability** | Low — automated tools (Mirai, Aisuru) scan entire IP ranges |
| **IronMesh Detection** | Tests top-100 default credential pairs with safe rate limiting; creates Critical vulnerability (CVSS 9.5) and alert |
| **Remediation** | Change all default passwords; disable unused management interfaces; implement account lockout policies |

### 3.2 Botnet Recruitment via Telnet/ADB

| Aspect | Detail |
|---|---|
| **Attack Surface** | Telnet (23), ADB (5555) — unauthenticated or weakly authenticated remote access |
| **Attacker Capability** | Low — botnets scan automatically; ADB requires no authentication |
| **IronMesh Detection** | Banner grab on port 23; CNXN banner detection on port 5555; immediate Critical alerts |
| **Remediation** | Disable Telnet entirely; disable ADB on production devices; use SSH with key-based auth |

### 3.3 Supply Chain Firmware Compromise

| Aspect | Detail |
|---|---|
| **Attack Surface** | Device firmware — pre-infected at manufacturing (BadBox 2.0) |
| **Attacker Capability** | High — requires supply chain access, but affects millions of devices |
| **IronMesh Detection** | Shannon entropy analysis (score >7.2 = encrypted/packed payload); suspicious string extraction (backdoor services, C2 indicators) |
| **Remediation** | Purchase from trusted vendors; verify firmware checksums; update to latest vendor firmware |

### 3.4 OT/ICS Protocol Exploitation

| Aspect | Detail |
|---|---|
| **Attack Surface** | Modbus (502), BACnet (47808) — industrial control protocols with no authentication |
| **Attacker Capability** | Medium — requires network access, but protocols have zero authentication by design |
| **IronMesh Detection** | Protocol fingerprinting via Modbus function code probes and BACnet headers; Critical scoring for any internet-reachable OT device |
| **Remediation** | Network segment OT devices; never expose Modbus/BACnet to internet; implement industrial firewalls |

### 3.5 Insecure Communication Interception

| Aspect | Detail |
|---|---|
| **Attack Surface** | MQTT (1883), HTTP (80), RTSP (554) — cleartext protocols transmitting sensitive data |
| **Attacker Capability** | Medium — requires network access (ARP spoofing, rogue AP, or physical tap) |
| **IronMesh Detection** | MQTT CONNECT packet testing on port 1883; RTSP OPTIONS without auth challenge; TLS version testing (flags 1.0/1.1) |
| **Remediation** | Enable TLS on all protocols (MQTTS on 8883, HTTPS on 443); require RTSP authentication; disable TLS 1.0/1.1 |

### 3.6 CISA KEV Exploitation

| Aspect | Detail |
|---|---|
| **Attack Surface** | Any device with firmware matching a CVE on the CISA Known Exploited Vulnerabilities list |
| **Attacker Capability** | Varies — KEV means the vulnerability is **actively exploited in the wild** |
| **IronMesh Detection** | Daily KEV feed sync; every discovered CVE cross-referenced against KEV catalog; automatic Critical severity escalation for KEV matches |
| **Remediation** | KEV entries include CISA-mandated remediation actions and due dates; patch immediately |

## 4. Limitations

- **Credential testing is semi-active**: IronMesh sends actual login attempts, which may trigger security tools or account lockout on monitored networks
- **Firmware analysis requires local files**: The firmware binary must be accessible to the analyzer service; IronMesh does not download firmware from devices
- **Entropy false positives**: Legitimate compressed firmware (e.g., gzip, LZMA) may score >7.2; operator review is required for entropy alerts
- **Network scanning requires privileges**: nmap needs raw socket access (`NET_ADMIN`, `NET_RAW` capabilities); must run as privileged container
- **No encrypted traffic analysis**: IronMesh does not perform MitM — it detects whether encryption is *present*, not what's *inside* encrypted traffic
- **Rate limiting on NVD API**: Without an API key, CVE lookups are limited to 5 requests per 30 seconds

## 5. Safe Scanning Guidelines

IronMesh implements these safety controls by default:

1. **Credential testing rate limit**: 500ms delay between attempts
2. **Maximum attempts**: 50 credential pairs per device per scan
3. **Lockout detection**: Stops immediately on HTTP 429 or lockout messages
4. **Audit logging**: Every credential test is logged with timestamp for accountability
5. **Non-destructive scanning**: nmap uses service detection, not exploitation
6. **Alert deduplication**: Same alert type + device suppressed for 24 hours to prevent fatigue

---

*Last updated: 2026-06-24*
