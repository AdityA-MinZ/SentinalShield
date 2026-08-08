# SentinelShield Log Samples

Sample lines taken from `evidence/sentinel-shield.log` (normal + attack traffic)
and `evidence/rate_limit_enforcement_main.log` (rate-limit test). Every event is
JSONL and contains a **timestamp**, a **client IP** (`client_ip`), and the event
**category** (`event`, `attack_type`, `rule_id`, or `status`).

## 1. Allowed request (HTTP 200) — with timestamp + IP

```json
{"timestamp": "2026-08-08T13:12:18.491368+00:00", "level": "INFO", "logger": "sentinel_shield", "message": "Request processed", "event": "access", "client_ip": "192.168.65.1", "method": "GET", "path": "/cart", "status": 200, "elapsed_ms": 20.69}
```

| Field | Value |
|---|---|
| Timestamp | `2026-08-08T13:12:18.491368+00:00` |
| Source IP | `192.168.65.1` |
| Result | allowed (200) |

## 2. Detection events distinguish attack categories

SQL Injection detection:

```json
{"timestamp": "2026-08-08T13:12:35.386473+00:00", "level": "WARNING", "logger": "sentinel_shield", "message": "Attack detected", "event": "detection", "client_ip": "192.168.65.1", "path": "/", "attack_type": "sqli", "rule_id": "SQLI-001"}
```

XSS detection:

```json
{"timestamp": "2026-08-08T13:12:35.468142+00:00", "level": "WARNING", "logger": "sentinel_shield", "message": "Attack detected", "event": "detection", "client_ip": "192.168.65.1", "path": "/", "attack_type": "xss", "rule_id": "XSS-001"}
```

The `attack_type` field clearly labels each event, so SQLi (`sqli`/`SQLI-xxx`)
can be told apart from XSS (`xss`/`XSS-xxx`). The same field is used for every
category: `lfi`, `ssrf`, `path_traversal`, `command_injection`, `file_upload`.

## 3. Blocked request (HTTP 403) — with reason

```json
{"timestamp": "2026-08-08T13:12:35.386687+00:00", "level": "WARNING", "logger": "sentinel_shield", "message": "Request blocked", "event": "block", "client_ip": "192.168.65.1", "path": "/", "reason_type": "AttackDetected", "reason": "sqli: SQLI-001"}
```

## 4. Rate-limited request (HTTP 429) — with timestamp + IP

```json
{"timestamp": "2026-08-08T13:34:22.597508+00:00", "level": "INFO", "logger": "sentinel_shield", "message": "Request processed", "event": "access", "client_ip": "192.168.65.1", "method": "GET", "path": "/login", "status": 429, "elapsed_ms": 0.19}
```

## 5. Full captures

- `evidence/sentinel-shield.log` — main proxy (baseline + attack traffic)
- `evidence/rate_limit_enforcement_main.log` — rate-limit enforcement test
