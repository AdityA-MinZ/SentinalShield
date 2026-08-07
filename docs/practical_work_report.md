# SentinelShield: Advanced Intrusion Detection & Web Protection System

## Practical Work Documentation

---

> **Student Name:** \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_
> **Date:** \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_
> **Institution:** \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Objectives](#2-objectives)
3. [System Architecture](#3-system-architecture)
4. [Technology Stack](#4-technology-stack)
5. [Component Deep-Dive](#5-component-deep-dive)
6. [Detection Rules Reference](#6-detection-rules-reference)
7. [Student Practical Workflow](#7-student-practical-workflow)
8. [Practical Outputs & Observations](#8-practical-outputs--observations)
9. [Troubleshooting](#9-troubleshooting)
10. [Conclusion & Future Work](#10-conclusion--future-work)

---

## 1. Project Overview

SentinelShield is a Python-based Web Application Firewall (WAF) and Intrusion Detection System (IDS) that protects web applications from common security threats. It operates as:
- **WSGI middleware** for Python web applications (Flask, Django, FastAPI)
- **Standalone reverse proxy** for non-Python applications (Node.js, PHP, etc.)
- **Rule-based detection engine** covering OWASP Top 10 vulnerabilities
- **Rate limiter** to prevent brute-force and DoS attacks
- **Dashboard** for real-time visualization of security events

The system simulates a realistic security operations environment where students can:
- Submit test attacks and observe detection
- Analyze security logs
- Interpret dashboard metrics
- Generate security reports

### 1.1 Key Features

| Feature | Description |
|---|---|
| **Real-time detection** | Inspects every request for SQLi, XSS, LFI, SSRF, path traversal, malicious file uploads |
| **Dual deployment modes** | WSGI middleware for Python apps + reverse proxy for any web server |
| **Rate limiting** | Token-bucket algorithm prevents brute-force and scraping |
| **IP reputation** | Allow/block lists for access control |
| **Structured logging** | JSON-formatted logs for analysis |
| **Dashboard** | Real-time charts, event feed, attack distribution |
| **Admin API** | REST API for monitoring and rule management |
| **CLI tool** | Status inspection, rule listing, report generation |
| **Docker support** | One-command deployment with Juice Shop demo |

---

## 2. Objectives

### 2.1 Practical Work Objectives

By the end of this practical work, students will be able to:

| # | Objective | Assessment |
|---|-----------|------------|
| 1 | Understand how modern WAFs detect threats using patterns, signatures, and rule engines | Architecture review + rule analysis |
| 2 | Analyze HTTP requests from a security perspective | Attack simulation exercises |
| 3 | Identify common web attacks using testing techniques | Detection observation + log analysis |
| 4 | Document findings and generate test reports | Summary report submission |
| 5 | Create meaningful analysis logs and summaries | Log examination worksheet |
| 6 | Understand attack detection → decision → logging → alerting → dashboarding workflow | Full exercise sequence |
| 7 | Demonstrate how rate limiting prevents brute-force/flooding attacks | Rate limiter exercise |

### 2.2 System Objectives

| # | Technical Objective | Status |
|---|-------------------|--------|
| 1 | WSGI middleware that inspects HTTP requests for malicious payloads | ✅ |
| 2 | Detect and block SQL Injection, XSS, LFI, SSRF, Path Traversal, File Upload, Command Injection | ✅ (44 rules) |
| 3 | Rate limiting and IP reputation for access control | ✅ |
| 4 | REST API for administration and monitoring | ✅ |
| 5 | Real-time dashboard for event visualization | ✅ |
| 6 | CLI for status, rule listing, and report generation | ✅ |
| 7 | Docker-based deployment for easy setup | ✅ |
| 8 | Demonstrate effectiveness against OWASP Juice Shop | ✅ |

---

## 3. System Architecture

### 3.1 High-Level Architecture Diagram

```
                         ┌──────────────────────────────────────────────────┐
                         │                SentinelShield                     │
                         │                                                    │
  ┌──────────┐          │  ┌──────────────┐    ┌──────────────────────┐      │
  │  Client   │ ──────► │  │  Request      │    │  Detection &         │      │
  │ (Browser) │          │  │  Receiver     │───►│  Protection Engine   │      │
  └──────────┘          │  │  (Proxy or    │    │                      │      │
                         │  │  Middleware)  │    │  ┌────────────────┐  │      │
                         │  └──────────────┘    │  │ Rules Engine    │  │      │
                         │         │            │  │ (44 rules)     │  │      │
                         │         ▼            │  ├────────────────┤  │      │
                         │  ┌──────────────┐    │  │ Rate Limiter   │  │      │
                         │  │  IP Check     │──►│  ├────────────────┤  │      │
                         │  │  (reputation) │    │  │ IP Reputation  │  │      │
                         │  └──────┬───────┘    │  └────────────────┘  │      │
                         │         │            └──────────────────────┘      │
                         │         ▼                    │                    │
                         │  ┌──────────────┐            ▼                    │
                         │  │  Logger +    │    ┌────────────────┐           │
                         │  │  Traffic     │◄───│  Decision      │           │
                         │  │  Analyzer    │    │  (Block / Allow)│           │
                         │  └──────┬───────┘    └────────────────┘           │
                         │         │                    │                    │
                         │         ▼                    ▼                    │
                         │  ┌──────────────────────────────────────┐         │
                         │  │        Output Channels               │         │
                         │  │  ┌────────┐ ┌────────┐ ┌─────────┐  │         │
                         │  │  │ Log    │ │Dashboard│ │  Admin  │  │         │
                         │  │  │ File   │ │(Flask) │ │  API    │  │         │
                         │  │  │        │ │:9091   │ │  :9090  │  │         │
                         │  │  └────────┘ └────────┘ └─────────┘  │         │
                         │  └──────────────────────────────────────┘         │
                         └──────────────────────────────────────────────────┘
                                      │
                                      ▼
                              ┌────────────────┐
                              │   Upstream      │
                              │   Application   │
                              │  (Juice Shop /  │
                              │   Flask App)    │
                              └────────────────┘
```

> **[Screenshot Placeholder: Architecture Diagram]**
> *Insert a screenshot or clean diagram here. The diagram above can be recreated using draw.io or Excalidraw.*

### 3.2 Request Processing Flow

When a request arrives, SentinelShield processes it through these stages:

```
1. RECEIVE ──► HTTP request arrives (method, path, headers, body, query)
                  │
2. IP CHECK ──► Is the client IP allowlisted? → Skip all checks → Forward
                  │ Is the client IP blocklisted? → Return 403 Forbidden
                  │
3. RATE CHECK ──► Has this IP exceeded its request limit?
                  │ Yes → Return 429 Too Many Requests
                  │ No → Deduct a token, continue
                  │
4. DETECTION ──► Scan all request parts (query, body, headers, cookies, path)
                  │ against compiled regex patterns
                  │ Match found?
                  │   BLOCK mode → Return 403 Forbidden
                  │   LOG mode → Log warning, continue
                  │
5. FORWARD ──► Request passed all checks → Send to upstream application
                  │
6. LOG ──► Record the event (timestamp, IP, method, path, status, duration)
                  │
7. ANALYZE ──► Update traffic stats (requests/sec, attack counts, top paths)
```

### 3.3 Component Interaction Diagram

```
┌────────────────────────────────────────────────────────────────────┐
│                     sentinel_shield Package                         │
│                                                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐            │
│  │    core/      │  │  detection/   │  │  protection/  │            │
│  │  engine.py    │  │ rules_engine │  │  waf.py       │            │
│  │  config.py    │  │ rules/*.yml  │  │  rate_limiter │            │
│  │  exceptions.py│  │              │  │  sanitizer    │            │
│  └──────┬───────┘  └──────┬───────┘  │  ip_reputation│            │
│         │                 │           └──────┬───────┘            │
│         └────────────┬────┘                  │                    │
│                      │                       │                    │
│  ┌──────────────┐  ┌───────┐  ┌──────────┐  │                    │
│  │  monitor/     │  │ api/  │  │  cli/    │  │                    │
│  │ traffic_analy│  │ server│  │  main.py │  │                    │
│  │ logger.py    │  │ schema│  │          │  │                    │
│  └──────┬───────┘  └───┬───┘  └────┬─────┘  │                    │
│         │              │            │        │                    │
│  ┌──────┴──────┐  ┌───┴────┐  ┌────┴─────┐  │                    │
│  │  dashboard/  │  │ proxy/ │  │  tests/  │  │                    │
│  │ server.py    │  │ proxy_ │  │ test_eng │  │                    │
│  │ templates/   │  │ server │  │ ine.py   │  │                    │
│  └─────────────┘  └────────┘  └──────────┘  │                    │
└────────────────────────────────────────────────────────────────────┘
```

---

## 4. Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| **Language** | Python 3.9+ | Cross-platform, extensive security libraries |
| **Core Engine** | WSGI (PEP 3333) | Compatible with Flask, Django, FastAPI |
| **Proxy Server** | aiohttp | Async HTTP reverse proxy |
| **Admin API** | FastAPI | REST API with auto-generated OpenAPI docs |
| **Dashboard** | Flask + Chart.js | Real-time security event visualization |
| **CLI** | Click | Command-line interface |
| **Configuration** | YAML (PyYAML) | Human-readable settings |
| **Validation** | Pydantic v2 | Runtime type checking |
| **Deployment** | Docker + Docker Compose | Containerized deployment |
| **Testing** | pytest | Unit testing framework |
| **Target App** | OWASP Juice Shop | Deliberately vulnerable web app for demo |

---

## 5. Component Deep-Dive

### 5.1 Core Engine (`sentinel_shield/core/engine.py`)

The `SentinelShield` class is a WSGI middleware that wraps any WSGI application. It implements the `__call__` method as defined in PEP 3333.

**How it works:**

1. Receives the WSGI `environ` dict and `start_response` callback
2. Extracts `client_ip`, `method`, `path` from the environment
3. Runs three sequential checks:
   - **IP Reputation Check** — Is this IP allowed?
   - **Rate Limit Check** — Has this IP exceeded its quota?
   - **Detection Check** — Does the request contain malicious patterns?
4. If all checks pass, forwards to the wrapped application
5. If any check fails, returns an error response (403/429)
6. Logs every request with timing information

**Key design:** The engine uses Python exceptions for control flow. `BlockedIP`, `RateLimitExceeded`, and `AttackDetected` exceptions are raised by the checking functions and caught at the middleware boundary, keeping detection logic clean and composable.

### 5.2 Detection Engine (`sentinel_shield/detection/rules_engine.py`)

The detection engine loads YAML rule files and evaluates incoming requests against compiled regex patterns.

**Rule Loading Process:**
- Scans the `rules/` directory for all `.yml` files
- Compiles each regex pattern with `re.IGNORECASE` for case-insensitive matching
- URL-decodes payloads (`unquote_plus`) before matching to handle encoded attacks
- Stores rules in memory for fast access

**Evaluation Process:**
- For each rule, extracts content from configured locations (query, body, headers, cookies, path, uri)
- Tests each compiled pattern against the extracted content
- Returns all matches with rule ID, attack type, confidence score, matched payload

**Example — SQL Injection Detection:**
```
Request: GET /?id=1'+OR+1=1--
Location: query string
Pattern: '\s*(OR|AND)\s+['"]?\w+['"]?\s*=
Step 1: URL decode → "id=1' OR 1=1--"
Step 2: Regex test → "' OR 1=" matches pattern
Step 3: Result → Match (SQLI-002, confidence 0.9)
```

### 5.3 Rate Limiter (`sentinel_shield/protection/rate_limiter.py`)

The rate limiter uses the **Token Bucket Algorithm**:

**Concept:** Each client IP has a bucket that fills with tokens at a steady rate. Each request consumes one token. If the bucket is empty, the request is denied.

```
Bucket Capacity (burst):  10 tokens
Refill Rate:              1 token/second (60 req/min)
Empty Bucket:             Requests are rejected with 429

Timeline:
  t=0  → Bucket: 10 tokens (full)
  t=0  → Request arrives → 9 tokens remaining
  t=1  → Request arrives → 8 tokens remaining
  t=2  → Request arrives → 7 tokens remaining
  ...
  t=10 → Bucket empty → Request REJECTED (429)
  t=11 → Refill: 1 token added → 1 token available
```

**Idle cleanup:** Buckets that have refilled to full capacity are removed after 5 minutes to prevent memory leaks.

### 5.4 IP Reputation (`sentinel_shield/protection/ip_reputation.py`)

Simple allow/block list manager:
- **Allowlist:** IPs in this list bypass all checks (typically trusted IPs like `127.0.0.1`)
- **Blocklist:** IPs in this list are immediately rejected with 403
- **Default state:** Unknown IPs are allowed (subject to detection checks)
- Dynamic management via Admin API or CLI

### 5.5 Logger (`sentinel_shield/monitor/logger.py`)

Produces structured JSON log entries for analysis:

**Log entry example (access):**
```json
{
  "timestamp": "2026-06-23T10:30:00.123456+00:00",
  "level": "INFO",
  "event": "access",
  "client_ip": "192.168.1.100",
  "method": "GET",
  "path": "/products",
  "status": 200,
  "elapsed_ms": 42.15
}
```

**Log entry example (blocked):**
```json
{
  "timestamp": "2026-06-23T10:30:05.654321+00:00",
  "level": "WARNING",
  "event": "block",
  "client_ip": "10.0.0.5",
  "path": "/",
  "reason_type": "AttackDetected",
  "reason": "[SQLI-001] Union-based SQL Injection matched for 10.0.0.5"
}
```

**Log entry example (rate limited):**
```json
{
  "timestamp": "2026-06-23T10:31:00.987654+00:00",
  "level": "WARNING",
  "event": "block",
  "client_ip": "10.0.0.99",
  "path": "/login",
  "reason_type": "RateLimitExceeded",
  "reason": "Rate limit exceeded for 10.0.0.99"
}
```

### 5.6 Traffic Analyzer (`sentinel_shield/monitor/traffic_analyzer.py`)

Maintains sliding-window statistics:
- Counts requests per HTTP method (GET, POST, etc.)
- Tracks status code distribution (2xx, 3xx, 4xx, 5xx)
- Identifies top requested paths
- Records attack type frequency
- Computes requests per second
- Window period: 300 seconds (configurable)

### 5.7 Dashboard (`sentinel_shield/dashboard/server.py`)

Flask-based web dashboard with real-time visualization:

**Dashboard Components:**

| Section | Content | Purpose |
|---|---|---|
| **Stats Row** | Total requests, attacks blocked, req/sec, rules loaded | Quick status overview |
| **Attack Distribution** | Bar chart by attack type | Which attacks are most common? |
| **Attack Timeline** | Line chart of blocked events over time | When do attacks spike? |
| **Recent Events** | Live feed of security events | Real-time monitoring |
| **Top Paths** | Most frequently targeted URLs | What's being attacked? |
| **Status Codes** | HTTP status distribution | How many succeeded/failed? |

> **[Screenshot Placeholder: Dashboard Overview]**
> *Insert a full-page screenshot of the dashboard at http://localhost:9091 showing the stats row, charts, and event feed.*

> **[Screenshot Placeholder: Attack Distribution Chart]**
> *Insert a screenshot of the bar chart showing attack types after running test_attacks.sh.*

### 5.8 Admin API (`sentinel_shield/api/server.py`)

FastAPI-based REST API:

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check with version and uptime |
| `/stats` | GET | Traffic statistics summary |
| `/rules` | GET | List all detection rules |
| `/config` | GET | Current system configuration |
| `/rate-limiter` | GET | Rate limiter status |
| `/ip-reputation` | GET | IP reputation status |
| `/ip` | POST | Block/unblock/allow IP addresses |
| `/reload-rules` | POST | Hot-reload rule files (no restart needed) |
| `/reset-stats` | POST | Reset traffic statistics |

### 5.9 Proxy Server (`sentinel_shield/proxy/proxy_server.py`)

Async reverse proxy for non-Python applications:
- Listens on a configurable port (default 8080)
- Reuses the same detection engine, rate limiter, and logger
- Forwards clean requests to upstream (e.g., Juice Shop on port 3000)
- Returns 403 for blocked requests
- Returns 502 if upstream is unavailable

### 5.10 CLI Tool (`sentinel_shield/cli/main.py`)

```
Usage: sentinel-shield [OPTIONS] COMMAND [ARGS]

Commands:
  proxy      Run as standalone reverse proxy
  wrap       Instructions for WSGI wrapping
  admin      Start the admin API server
  dashboard  Start the web dashboard
  report     Generate security summary report
  status     Check current SentinelShield status
  rules      List detection rules
```

---

## 6. Detection Rules Reference

### 6.1 Rule Format

Each rule is defined in YAML format:

```yaml
attack_type: sqli                       # Attack category
rules:
  - id: SQLI-001                        # Unique identifier
    name: "Union-based SQL Injection"   # Human-readable name
    severity: critical                   # critical | high | medium | low
    severity_weight: 1.0                # Confidence multiplier (0.0–1.0)
    confidence: 0.95                    # Base detection confidence
    locations: [query, body]            # Request parts to inspect
    patterns:                           # Regex patterns (Python syntax)
      - "UNION\\s+(ALL\\s+)?SELECT"
      - "UNION\\s+SELECT.*FROM"
    action: block                        # Action when matched
```

### 6.2 Attack Categories

#### SQL Injection (8 rules)
Detects attempts to manipulate database queries through user input.

| Rule ID | Name | Severity | Key Patterns |
|---------|------|----------|--------------|
| SQLI-001 | Union-based SQLi | Critical | `UNION SELECT`, `UNION ALL SELECT` |
| SQLI-002 | Boolean-based SQLi | Critical | `' OR 1=1`, `' AND '1'='1` |
| SQLI-003 | Time-based SQLi | Critical | `SLEEP()`, `WAITFOR DELAY`, `BENCHMARK` |
| SQLI-004 | Error-based SQLi | High | `EXTRACTVALUE()`, `UPDATEXML()`, `CONVERT()` |
| SQLI-005 | Stacked Queries | Critical | `; DROP`, `; DELETE`, `; INSERT` |
| SQLI-006 | Comment-based SQLi | High | `--`, `#`, `/**/` |
| SQLI-007 | Inline SQLi | High | `OR 1=1`, `1=1`, `'=''` |
| SQLI-008 | Schema Access | High | `INFORMATION_SCHEMA`, `sqlite_master`, `pg_catalog` |

#### Cross-Site Scripting (8 rules)
Detects attempts to inject client-side scripts into web pages.

| Rule ID | Name | Severity | Key Patterns |
|---------|------|----------|--------------|
| XSS-001 | Script Tag Injection | Critical | `<script>...</script>` |
| XSS-002 | Event Handler Injection | Critical | `onerror=`, `onload=`, `onclick=` |
| XSS-003 | JavaScript URI Scheme | High | `javascript:`, `vbscript:`, `data:text/html` |
| XSS-004 | HTML Attribute Injection | High | `src=javascript:`, `href=javascript:` |
| XSS-005 | Encoded XSS | High | `%3Cscript`, `&lt;script`, `&#60;script` |
| XSS-006 | Template Injection | High | `{{ }}`, `${ }`, `<%= %>` |
| XSS-007 | DOM-based XSS | High | `document.write()`, `eval()`, `innerHTML=` |
| XSS-008 | Stylesheet Injection | Medium | `expression()`, `-moz-binding`, `@import` |

#### Local File Inclusion (6 rules)
Detects attempts to read arbitrary files on the server.

| Rule ID | Name | Severity | Key Patterns |
|---------|------|----------|--------------|
| LFI-001 | Directory Traversal | Critical | `../`, `..\\`, `%2e%2e%2f` |
| LFI-002 | System File Access | Critical | `/etc/passwd`, `/etc/shadow`, `/proc/self/` |
| LFI-003 | Log File Access | High | `/var/log/` |
| LFI-004 | Wrapper Protocol | Critical | `php://filter`, `file://`, `expect://` |
| LFI-005 | Windows File Access | High | `boot.ini`, `system32`, `ntuser.dat` |
| LFI-006 | App File Access | High | `wp-config.php`, `.env`, `config.php` |

#### Server-Side Request Forgery (5 rules)
Detects attempts to make the server access internal resources.

| Rule ID | Name | Severity | Key Patterns |
|---------|------|----------|--------------|
| SSRF-001 | Internal IP Access | Critical | `127.0.0.1`, `10.x.x.x`, `192.168.x.x` |
| SSRF-002 | Cloud Metadata | Critical | `169.254.169.254`, `metadata.google` |
| SSRF-003 | Internal Service Discovery | High | `*.internal`, `consul.`, `vault.`, `kubernetes` |
| SSRF-004 | Private IP Obfuscation | High | `0x7f000001`, `2130706433` (integer IP) |
| SSRF-005 | DNS Rebinding | Medium | `*.xip.io`, `*.nip.io`, `localtest.me` |

#### Path Traversal (4 rules)
Detects encoded and obfuscated directory traversal attempts.

| Rule ID | Name | Severity | Key Patterns |
|---------|------|----------|--------------|
| PT-001 | Directory Traversal Sequences | Critical | `../`, `%2e%2e%2f`, `%c0%ae%c0%ae/` |
| PT-002 | Absolute Path Access | High | Root paths, Windows drive letters |
| PT-003 | Sensitive File Patterns | High | `.env`, `.key`, `.pem`, config files |
| PT-004 | Encoded Path Traversal | High | `%2e%2e/etc/passwd`, `%2fproc%2fself` |

#### Malicious File Upload (5 rules)
Detects attempts to upload executable or dangerous files.

| Rule ID | Name | Severity | Key Patterns |
|---------|------|----------|--------------|
| FU-001 | Executable File Upload | Critical | `.exe`, `.dll`, `.so`, `.sh`, `.py` |
| FU-002 | Web Shell Upload | Critical | `.php`, `.asp`, `.jsp`, `.cgi` |
| FU-003 | Double Extension Upload | High | `.php.jpg`, `.asp.png` |
| FU-004 | Hidden File Upload | Medium | `.htaccess`, `.env`, `.git` |
| FU-005 | Content-Type Mismatch | High | Suspicious MIME types |

#### OS Command Injection (8 rules)
Detects attempts to execute arbitrary operating system commands through user input.

| Rule ID | Name | Severity | Key Patterns |
|---------|------|----------|--------------|
| CMD-001 | Shell Metacharacter Injection | Critical | `;`, `&&`, `\|`, backticks, `$()` |
| CMD-002 | Encoded or Newline Injection | Critical | `%0a`, `%0d`, `\r\n` before commands |
| CMD-003 | Command Interpreter Invocation | Critical | `sh -c`, `bash -c`, `cmd.exe /c`, `powershell` |
| CMD-004 | System Command Keywords | High | `whoami`, `uname -a`, `ifconfig`, `netstat` |
| CMD-005 | File Manipulation Commands | High | `rm -rf`, `chmod 777`, `chown`, `mv` |
| CMD-006 | Network / Exfiltration Tools | High | `wget`, `curl`, `nc`, `ncat`, `socat` |
| CMD-007 | IFS Whitespace Bypass | High | `${IFS}`, `$IFS` |
| CMD-008 | Obfuscated / Piped Execution | Critical | `base64 -d`, `echo ... \| bash` |

### 6.3 Rule Coverage Summary

| Category | Rules | Critical | High | Medium |
|----------|-------|----------|------|--------|
| SQL Injection | 8 | 5 | 3 | 0 |
| XSS | 8 | 2 | 5 | 1 |
| LFI | 6 | 3 | 3 | 0 |
| SSRF | 5 | 2 | 2 | 1 |
| Path Traversal | 4 | 1 | 3 | 0 |
| File Upload | 5 | 2 | 2 | 1 |
| Command Injection | 8 | 4 | 4 | 0 |
| **Total** | **44** | **19** | **22** | **3** |

---

## 7. Student Practical Workflow

This section describes the step-by-step workflow that students must follow.

### Step 1: Setup and Architecture Review

**Duration:** 30 minutes

**Activities:**
1. Clone/access the SentinelShield project
2. Review the directory structure
3. Start the system:
   ```bash
   cd ~/Documents/SentinelShield
   source venv/bin/activate
   
   # Start the dashboard (Terminal 1)
   sentinel-shield dashboard --port 9091
   
   # Start the proxy + Juice Shop (Terminal 2, requires Docker)
   docker-compose up -d
   ```
4. Open the dashboard at `http://localhost:9091`

**Deliverable:** Annotated architecture diagram showing component interactions.

### Step 2: Rule Definitions Review

**Duration:** 30 minutes

**Activities:**
1. List all rules:
   ```bash
   sentinel-shield rules
   ```
2. Examine specific rules:
   ```bash
   sentinel-shield rules SQLI-001
   sentinel-shield rules XSS-001
   ```
3. Read the YAML rule files:
   ```bash
   cat sentinel_shield/detection/rules/sqli.yml
   ```
4. For each rule, identify:
   - What attack does it detect?
   - Where in the request does it look? (query, body, headers, cookies?)
   - What regex pattern triggers detection?
   - What is its severity level?

**Deliverable:** Completed rule summary table.

### Step 3: Simulate HTTP Requests

**Duration:** 45 minutes

**Activities:**
1. Send normal requests:
   ```bash
   curl http://localhost:8080/
   curl http://localhost:8080/?search=laptop
   curl http://localhost:8080/about
   ```
2. Send malicious test payloads:
   ```bash
   curl http://localhost:8080/?id=1'+OR+1=1--
   curl http://localhost:8080/?q=<script>alert(1)</script>
   curl http://localhost:8080/?file=../../../etc/passwd
   ```
3. Use the automated test script:
   ```bash
   ./scripts/test_attacks.sh http://localhost:8080
   ```
4. Simulate normal traffic:
   ```bash
   ./scripts/normal_traffic.sh http://localhost:8080 15
   ```
5. Simulate brute-force (rate limiting):
   ```bash
   ./scripts/brute_force.sh http://localhost:8080 30 0.05
   ```

**Deliverable:** Completed attack simulation results table.

### Step 4: Observe Detection Behavior

**Duration:** 30 minutes

**Activities:**
1. Compare normal vs. malicious request outcomes
2. Document for each request:
   - Was it blocked or allowed?
   - What detection category triggered? (SQLi, XSS, etc.)
   - What was the HTTP response status?
   - How did the system respond?

3. Check the dashboard for the impact of your attacks:
   - Attack counts increased
   - Timeline shows spikes
   - Recent events list shows blocks

**Deliverable:** Detection observation notes with screenshots.

### Step 5: Log File Examination

**Duration:** 30 minutes

**Activities:**
1. Open the log file:
   ```bash
   cat sentinel-shield.log | wc -l      # Count total entries
   tail -50 sentinel-shield.log | less  # View latest entries
   ```
2. Count events by type:
   ```bash
   grep -c '"event": "access"' sentinel-shield.log
   grep -c '"event": "block"' sentinel-shield.log
   grep -c '"event": "detection"' sentinel-shield.log
   ```
3. Find the most frequent attack type:
   ```bash
   grep '"attack_type"' sentinel-shield.log | sort | uniq -c | sort -rn
   ```
4. Find the most active IP:
   ```bash
   grep '"client_ip"' sentinel-shield.log | sort | uniq -c | sort -rn | head -5
   ```
5. Generate a structured report:
   ```bash
   sentinel-shield report --format markdown
   ```

> **[Screenshot Placeholder: Log File Analysis]**
> *Insert a screenshot showing log file contents with highlighted blocked entries.*

**Deliverable:** Completed log analysis table and summary statistics.

### Step 6: Dashboard Interpretation

**Duration:** 30 minutes

**Activities:**
1. Refresh the dashboard at `http://localhost:9091`
2. Interpret each dashboard component:
   - **Stats Row:** What do the numbers tell you?
   - **Attack Distribution Chart:** Which attack type is most common?
   - **Attack Timeline:** Are there patterns in when attacks occur?
   - **Recent Events:** What information is available for each event?
   - **Top Paths:** Which endpoints are targeted most?
3. Identify trends and anomalies

> **[Screenshot Placeholder: Dashboard After Attacks]**
> *Insert a screenshot of the dashboard after running all exercise scripts, showing elevated attack counts.*

**Deliverable:** Dashboard interpretation notes with observed metrics.

### Step 7: Reporting and Analysis

**Duration:** 45 minutes

**Activities:**
1. Generate the security report:
   ```bash
   sentinel-shield report --format markdown
   ```
2. Export the report to a file:
   ```bash
   sentinel-shield report --format markdown > security_report.md
   ```
3. Compile your practical journal including:
   - Purpose of each experiment
   - Tools used
   - Step-by-step execution
   - Observations with screenshots
   - Interpretation of logs

4. Write a final report covering:
   - Total attacks performed
   - Detection accuracy
   - False positives and false negatives observed
   - Rate limiting effectiveness
   - Security recommendations

**Deliverable:** Complete practical journal + final security report.

---

## 8. Practical Outputs & Observations

### 8.1 Sample Attack Simulation Results

After running `./scripts/test_attacks.sh http://localhost:8080`:

```
=== Results: 22 passed, 0 failed ===

STATUS  TEST                                               HTTP
------  ----                                               ----
PASS    Union-based SQLi in query                          403
PASS    Boolean-based SQLi (OR 1=1)                        403
PASS    Comment-based SQLi (trailing --)                   403
PASS    Time-based SQLi (SLEEP)                            403
PASS    Stacked query (DROP)                               403
PASS    Script tag injection                               403
PASS    Event handler (onerror)                            403
PASS    JavaScript URI scheme                              403
PASS    Encoded XSS (%3Cscript)                            403
PASS    HTML attribute injection                           403
PASS    Directory traversal (../)                          403
PASS    System file access (/etc/shadow)                   403
PASS    PHP wrapper (php://filter)                         403
PASS    Windows file (boot.ini)                            403
PASS    Log file access                                    403
PASS    Internal IP (127.0.0.1)                            403
PASS    Cloud metadata (169.254.169.254)                   403
PASS    Internal hostname (localhost)                      403
PASS    Private IP (192.168.1.1)                           403
PASS    Encoded traversal (%2e%2e%2f)                     403
PASS    Double-encoded traversal (%252e)                   403
PASS    Normal homepage request                            200
PASS    Normal search query                                200
PASS    Normal path request                                200
```

> **[Screenshot Placeholder: Attack Simulation Terminal Output]**
> *Insert a screenshot showing the terminal output of test_attacks.sh.*

### 8.2 Sample Log Entry Analysis

| Timestamp | IP | Event | Attack Type | Rule ID |
|-----------|----|-------|-------------|---------|
| 10:30:01 | 192.168.1.5 | block | sqli | SQLI-002 |
| 10:30:02 | 192.168.1.5 | block | xss | XSS-001 |
| 10:30:03 | 192.168.1.5 | block | lfi | LFI-001 |
| 10:30:05 | 192.168.1.10 | block | ssrf | SSRF-001 |
| 10:30:06 | 192.168.1.10 | block | command_injection | CMD-001 |
| 10:31:00 | 10.0.0.99 | block | RateLimitExceeded | — |

### 8.3 Summary Report Template

```
# SentinelShield Security Report

- **Total requests:** 127
- **Blocked/detected:** 24

## Attack Distribution

| Attack Type | Count |
|------------|-------|
| sqli | 8 |
| xss | 5 |
| lfi | 4 |
| ssrf | 3 |
| path_traversal | 2 |
| file_upload | 0 |
| command_injection | 3 |
| RateLimitExceeded | 2 |

## Top IPs

| IP | Requests |
|----|----------|
| 192.168.1.5 | 15 |
| 10.0.0.99 | 30 |
| 192.168.1.10 | 8 |

## Recent Security Events

| Time | IP | Type | Rule |
|------|----|------|------|
| 10:31:00 | 10.0.0.99 | RateLimitExceeded | Rate limit exceeded |
| 10:30:05 | 192.168.1.10 | ssrf | [SSRF-001] Internal IP |
| 10:30:03 | 192.168.1.5 | lfi | [LFI-001] Directory Traversal |
| 10:30:02 | 192.168.1.5 | xss | [XSS-001] Script Tag |
| 10:30:01 | 192.168.1.5 | sqli | [SQLI-002] Boolean SQLi |
```

> **[Screenshot Placeholder: CLI Report Output]**
> *Insert a screenshot of the `sentinel-shield report --format markdown` output.*

---

## 9. Troubleshooting

### 9.1 Common Issues

| Problem | Likely Cause | Solution |
|---------|-------------|----------|
| `sentinel-shield: command not found` | Package not installed | `pip install -e .` in the venv |
| Dashboard not loading | Flask not installed | `pip install flask` |
| 502 Bad Gateway from proxy | Upstream not running | Check `docker-compose ps` |
| Rules not loading | Wrong path in config | Check `rules_dir` in `sentinel-shield.yml` |
| Rate limiter not triggering | `burst_size` too high | Lower to 2–3 for demo |
| Log file empty | Wrong log path | Check `logging.file` in config |

### 9.2 Quick Start Checklist

- [ ] Virtual environment activated (`source venv/bin/activate`)
- [ ] Package installed (`pip install -e .`)
- [ ] Flask installed (`pip install flask`)
- [ ] Docker running (for Juice Shop demo)
- [ ] Config file exists (`sentinel-shield.yml`)
- [ ] Rules directory exists with `.yml` files
- [ ] Dashboard accessible at `http://localhost:9091`
- [ ] Proxy accessible at `http://localhost:8080`

---

## 10. Conclusion & Future Work

### 10.1 What We Built

| Component | Lines of Code | Purpose |
|-----------|--------------|---------|
| Core Engine | ~150 | WSGI middleware + request processing |
| Detection Rules | 44 rules | 7 attack categories |
| Rate Limiter | ~80 | Token bucket algorithm |
| IP Reputation | ~60 | Allow/block list management |
| Logger | ~100 | Structured JSON logging |
| Traffic Analyzer | ~100 | Sliding-window stats |
| Dashboard | ~150 (server) + ~300 (HTML/JS) | Real-time visualization |
| Admin API | ~150 | REST API with 9 endpoints |
| Proxy Server | ~150 | Async reverse proxy |
| CLI | ~250 | 7 commands |
| Tests | ~380 | 15 unit tests |
| **Total** | **~1,700** | |

### 10.2 Security Concepts Demonstrated

Through this practical work, students engage with:
- **Signature-based detection** — Regex patterns for known attack patterns
- **Request inspection** — Analyzing every part of an HTTP request
- **Rate limiting** — Preventing abuse through token bucket algorithm
- **Access control** — IP allow/block lists
- **Security logging** — Structured JSON logs for analysis
- **Event correlation** — Connecting detection events to dashboard metrics
- **Report generation** — Transforming raw logs into actionable summaries

### 10.3 Limitations

- Rule-based detection cannot catch zero-day or heavily obfuscated attacks
- No SSL/TLS termination (relies on upstream server)
- Rate limiter is per-process (not shared across instances)
- Statistics are in-memory (lost on restart)

### 10.4 Future Enhancements

| Enhancement | Description |
|---|---|
| **ML anomaly detection** | Statistical models for behavioral anomalies |
| **Persistent storage** | PostgreSQL/Redis for shared state |
| **Real-time alerts** | Email, Slack, webhook notifications |
| **Geo-IP blocking** | Block traffic from specific countries |
| **CSRF protection** | Token validation and cookie signing |
| **Kubernetes support** | Helm chart for production deployments |
| **Log aggregation** | Export to ELK, Splunk, or Loki |
| **Performance mode** | C-based regex engine for high throughput |

---

## Appendix A: Project Structure

```
SentinelShield/
├── sentinel_shield/
│   ├── __init__.py                 # Package root (exposes SentinelShield)
│   ├── core/
│   │   ├── engine.py               # WSGI middleware orchestrator
│   │   ├── config.py               # YAML configuration loader
│   │   └── exceptions.py           # Custom exception classes
│   ├── detection/
│   │   ├── rules_engine.py         # Pattern matching engine
│   │   └── rules/                   # YAML rule definitions
│   │       ├── sqli.yml            # SQL Injection (8 rules)
│   │       ├── xss.yml             # Cross-Site Scripting (8 rules)
│   │       ├── lfi.yml             # Local File Inclusion (6 rules)
│   │       ├── ssrf.yml            # SSRF (5 rules)
│   │       ├── path_traversal.yml  # Path Traversal (4 rules)
│   │       ├── file_upload.yml     # File Upload (5 rules)
│   │       └── command_injection.yml # Command Injection (8 rules)
│   ├── protection/
│   │   ├── waf.py                  # WAF middleware adapter
│   │   ├── rate_limiter.py         # Token bucket rate limiter
│   │   ├── sanitizer.py            # Input sanitization helpers
│   │   └── ip_reputation.py        # IP allow/block list manager
│   ├── monitor/
│   │   ├── traffic_analyzer.py     # Sliding-window traffic stats
│   │   └── logger.py               # Structured JSON logger
│   ├── api/
│   │   ├── server.py               # FastAPI admin server
│   │   └── schemas.py              # Pydantic request/response models
│   ├── dashboard/
│   │   ├── server.py               # Flask dashboard server
│   │   └── templates/
│   │       └── dashboard.html      # Dashboard UI with Chart.js
│   ├── proxy/
│   │   └── proxy_server.py         # Async reverse proxy (aiohttp)
│   └── cli/
│       └── main.py                 # Click CLI (7 commands)
├── tests/
│   └── test_engine.py              # 15 unit tests
├── scripts/
│   ├── test_attacks.sh             # 30 attack simulations + 3 normal
│   ├── normal_traffic.sh           # Legitimate traffic generator
│   ├── brute_force.sh              # Rate limiting test
│   └── run_all_exercises.sh        # Master exercise runner
├── docs/
│   ├── practical_work_report.md    # This document
│   └── student_worksheet.md        # Guided practical tasks
├── docker-compose.yml              # Docker deployment
├── Dockerfile                      # Container image
├── sentinel-shield.yml             # Default configuration
├── requirements.txt                # Python dependencies
└── pyproject.toml                  # Project metadata
```

## Appendix B: CLI Reference

```bash
sentinel-shield [OPTIONS] COMMAND [ARGS]

Commands:
  proxy      Run as standalone reverse proxy for Juice Shop demo
  wrap       Instructions for integrating as WSGI middleware
  admin      Start the FastAPI admin server on port 9090
  dashboard  Start the Flask dashboard on port 9091
  report     Generate a security summary report from logs
  status     Show system status and configuration
  rules      List detection rules or show rule details

Global Options:
  --help     Show help message
  --version  Show version (1.0.0)

Examples:
  sentinel-shield status
  sentinel-shield rules
  sentinel-shield rules SQLI-001
  sentinel-shield report
  sentinel-shield report --format markdown
  sentinel-shield dashboard --port 9091
  sentinel-shield proxy --upstream http://localhost:3000
```

## Appendix C: Docker Quick Reference

```bash
# Start everything
docker-compose up -d

# View logs
docker-compose logs -f sentinel-shield

# Stop everything
docker-compose down

# Rebuild after changes
docker-compose build sentinel-shield

# Access Juice Shop (unprotected)
curl http://localhost:3000

# Access Juice Shop (protected by SentinelShield)
curl http://localhost:8080
```

## Appendix D: Student Submission Checklist

Before submitting your practical work, ensure you have completed:

- [ ] **Architecture diagram** — Annotated with component descriptions
- [ ] **Rule summary table** — All 44 rules with attack type, severity, and locations
- [ ] **Attack simulation results** — Table with payloads, expected vs actual status codes
- [ ] **Log analysis** — Log entries decoded and categorized
- [ ] **Dashboard screenshots** — At least 2 screenshots showing stats and charts
- [ ] **Rate limiting demonstration** — Results showing before/after rate limit
- [ ] **CLI report** — Generated with `sentinel-shield report --format markdown`
- [ ] **False positive analysis** — Were any legitimate requests blocked?
- [ ] **Security recommendations** — At least 3 recommendations
- [ ] **Practical journal** — Step-by-step execution notes with observations

---

*Document prepared for internship practical work demonstration.*
*SentinelShield v1.0.0 — June 2026*
