# SentinelShield — Evidence Summary Tables

Numbers derived from `evidence/requests_table.md` and `evidence/rate_limit_table.md`
(full per-request analysis generated from the raw JSONL logs).

## 1. Malicious request count

| Metric | Count |
|---|---|
| Total requests observed | 50 |
| Legitimate requests allowed (HTTP 200) | 20 |
| Malicious requests blocked (HTTP 403) | 30 |
| Attack detection rate | 30 / 30 = 100% |
| False positives (legitimate requests blocked) | 0 |

## 2. Category distribution

Per-request primary detection (from the log's block reasons):

| Category | Payloads sent | Blocked | Detection rate |
|---|---|---|---|
| SQL Injection | 5 | 5 | 100% |
| XSS | 5 | 5 | 100% |
| LFI | 5 | 5 | 100% |
| SSRF | 4 | 4 | 100% |
| Path Traversal | 2 | 2 | 100% (caught by LFI-001) |
| Command Injection | 9 | 9 | 100% |
| **Total** | **30** | **30** | **100%** |

Note: some payloads matched more than one rule, so the raw log contains 64
rule-level detection events for the 30 requests (e.g. `command_injection` fired
17 times for 9 payloads). The table above shows one primary category per request.

## 3. Repeatedly flagged IP addresses

| IP | Requests | Context |
|---|---|---|
| `192.168.65.1` | 50 | All main-proxy traffic (Docker bridge gateway) |
| `127.0.0.1` | 40 | All rate-limit test traffic (dedicated proxy) |

Every request in each experiment came from a single source IP because Docker
network-maps all local client connections to the bridge gateway IP. On a real
network each client has its own IP, so this aggregation would identify specific
abusers — the brute-force run demonstrates the pattern (one IP flooding
`/login`).

## 4. Rate-limit enforcement test (current config: 50 req/min, burst 20)

| Metric | Value |
|---|---|
| Total requests sent | 40 |
| Allowed (HTTP 200) | 19 |
| Blocked (HTTP 429) | 21 |
| Requests before first block | 18 (burst consumed) |
| `RateLimitExceeded` log events | 21 |

Full output: `evidence/rate_limit_enforcement.log`
Per-request analysis: `evidence/rate_limit_enforcement_table.md`
