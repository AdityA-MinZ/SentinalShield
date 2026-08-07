# SentinelShield — Student Practical Worksheet

**Student Name:** \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_  
**Date:** \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_  
**Target URL:** \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

---

## Task 1: System Architecture Review

**Objective:** Understand how SentinelShield's components interact.

1. Start SentinelShield and the dashboard:
   ```bash
   sentinel-shield dashboard --port 9091
   ```

2. Open the dashboard at `http://localhost:9091` and identify each section.

3. Draw the system architecture diagram in the box below (or attach separately):

   ```
   ┌──────────┐     ┌──────────┐     ┌──────────┐
   │          │     │          │     │          │
   │          │ ──► │          │ ──► │          │
   │          │     │          │     │          │
   └──────────┘     └──────────┘     └──────────┘
   ```

4. **Questions:**
   - What happens to a request when it arrives at SentinelShield?
   - What three checks does each request go through?
   - What is the difference between LOG mode and BLOCK mode?

**Observations:**
\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_
\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

---

## Task 2: Rule Definitions Review

**Objective:** Examine the detection rules and understand how attacks are identified.

1. List all rules:
   ```bash
   sentinel-shield rules
   ```

2. View a specific rule in detail:
   ```bash
   sentinel-shield rules SQLI-001
   sentinel-shield rules XSS-001
   sentinel-shield rules LFI-001
   sentinel-shield rules CMD-001
   ```

3. Examine the rule YAML files directly:
   ```bash
   cat sentinel_shield/detection/rules/sqli.yml | head -30
   ```

4. **Questions:**
   - How many total rules are loaded?
   - What are the 7 attack categories covered?
   - For SQLI-001, what patterns does it look for and in which parts of the request?
   - What is the difference between severity levels (critical, high, medium)?

**Rule Summary Table:**

| Rule ID | Attack Type | Severity | Locations | Pattern Count |
|---------|------------|----------|-----------|--------------|
|         |            |          |           |              |
|         |            |          |           |              |
|         |            |          |           |              |

---

## Task 3: Simulate Attacks — Observe Detection

**Objective:** Submit malicious requests and observe how SentinelShield responds.

### Part A: SQL Injection

Run each request and record the HTTP status code:

| # | Payload | Expected | Actual | Blocked? |
|---|---------|----------|--------|----------|
| 1 | `curl "http://localhost:8080/?id=1'+OR+1=1--"` | 403 | | |
| 2 | `curl "http://localhost:8080/?q=1 UNION SELECT * FROM users"` | 403 | | |
| 3 | `curl "http://localhost:8080/?id=1'+SLEEP(5)--"` | 403 | | |

### Part B: Cross-Site Scripting

| # | Payload | Expected | Actual | Blocked? |
|---|---------|----------|--------|----------|
| 4 | `curl "http://localhost:8080/?q=<script>alert(1)</script>"` | 403 | | |
| 5 | `curl "http://localhost:8080/?q=javascript:alert(1)"` | 403 | | |
| 6 | `curl "http://localhost:8080/?q=%3Cscript%3Ealert(1)%3C/script%3E"` | 403 | | |

### Part C: Local File Inclusion

| # | Payload | Expected | Actual | Blocked? |
|---|---------|----------|--------|----------|
| 7 | `curl "http://localhost:8080/?file=../../../etc/passwd"` | 403 | | |
| 8 | `curl "http://localhost:8080/?file=php://filter/convert.base64-encode/resource=index.php"` | 403 | | |

### Part D: Server-Side Request Forgery

| # | Payload | Expected | Actual | Blocked? |
|---|---------|----------|--------|----------|
| 9 | `curl "http://localhost:8080/?url=http://169.254.169.254/"` | 403 | | |
| 10 | `curl "http://localhost:8080/?url=http://127.0.0.1:80"` | 403 | | |

### Part E: OS Command Injection

| # | Payload | Expected | Actual | Blocked? |
|---|---------|----------|--------|----------|
| 11 | `curl "http://localhost:8080/?cmd=1;whoami"` | 403 | | |
| 12 | `curl "http://localhost:8080/?cmd=ls+-la"` | 403 | | |
| 13 | `curl "http://localhost:8080/?cmd=1&&cat+/etc/passwd"` | 403 | | |
| 14 | `curl "http://localhost:8080/?cmd=sh+-c+whoami"` | 403 | | |
| 15 | `curl "http://localhost:8080/?cmd=%24%7BIFS%7Dwhoami"` | 403 | | |

### Part F: Normal Requests (Control Group)

| # | Payload | Expected | Actual | Blocked? |
|---|---------|----------|--------|----------|
| 16 | `curl "http://localhost:8080/"` | 200 | | |
| 17 | `curl "http://localhost:8080/?search=laptop"` | 200 | | |
| 18 | `curl "http://localhost:8080/about"` | 200 | | |

**Questions:**
- Which attacks were successfully detected and blocked?
- Were any normal requests incorrectly flagged (false positives)?
- What patterns in the SQLi payload triggered the detection?

**Observations:**
\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_
\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

---

## Task 4: Examine Security Logs

**Objective:** Read and interpret security events from the log file.

1. Check the log file:
   ```bash
   cat sentinel-shield.log | tail -30
   ```

2. Pick 3 log entries and complete the table:

| Timestamp | IP Address | Event Type | Attack Type | Rule ID |
|-----------|-----------|------------|-------------|---------|
|           |           |            |             |         |
|           |           |            |             |         |
|           |           |            |             |         |

3. Count events by type:
   ```bash
   grep -c '"event": "block"' sentinel-shield.log
   grep -c '"event": "detection"' sentinel-shield.log
   grep -c '"event": "access"' sentinel-shield.log
   ```

4. **Questions:**
   - How many total access events were logged?
   - How many blocked events?
   - What is the most frequent attack type in the logs?
   - Which IP address appears most frequently?

**Log Analysis:**
\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_
\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

---

## Task 5: Dashboard Analysis

**Objective:** Interpret the dashboard visualizations.

1. Open `http://localhost:9091` in a browser.

2. After running the attack simulations, observe and record:

   | Metric | Value |
   |--------|-------|
   | Total Requests | |
   | Attacks Blocked | |
   | Requests/Sec | |
   | Most Common Attack Type | |
   | Top Path | |
   | Most Frequent Status Code | |

3. **Dashboard Section Analysis:**
   - **Attack Distribution Chart:** Which attack type was most frequent? Why do you think that is?
   - **Attack Timeline:** Are there spikes in blocked requests? When did they occur?
   - **Recent Security Events:** What patterns do you see in the event log?
   - **Top Paths:** Which endpoint received the most attack attempts?

**Dashboard Observations:**
\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_
\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

---

## Task 6: Rate Limiting Demonstration

**Objective:** Observe how SentinelShield prevents brute-force attacks.

1. Run the brute-force simulation:
   ```bash
   ./scripts/brute_force.sh http://localhost:8080 30 0.05
   ```

2. Record results:

   | Metric | Value |
   |--------|-------|
   | Total requests sent | |
   | Requests allowed | |
   | Requests blocked | |
   | Requests before first block | |

3. Check the log for rate-limit events:
   ```bash
   grep -c "RateLimitExceeded\|rate_limit" sentinel-shield.log
   ```

4. **Questions:**
   - After how many requests did the rate limiter activate?
   - What HTTP status code does the rate limiter return?
   - How would you adjust the rate limiter settings for a high-traffic website?
   - What other methods could protect against brute-force attacks?

**Rate Limiting Observations:**
\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_
\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

---

## Summary Report Template

### Detection Results

| Attack Category | Attempts | Blocked | Detection Rate |
|----------------|----------|---------|---------------|
| SQL Injection | | | % |
| XSS | | | % |
| LFI | | | % |
| SSRF | | | % |
| Path Traversal | | | % |
| Command Injection | | | % |
| Normal Requests | | | % (false positives) |

### Security Recommendations

Based on your observations, list 3 recommendations for improving security:

1. \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_
2. \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_
3. \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

### False Positive Analysis

Were any legitimate requests incorrectly blocked? If yes, describe them and suggest how the rule could be improved:

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_
\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

---

*End of Worksheet — Submit with your practical report.*
