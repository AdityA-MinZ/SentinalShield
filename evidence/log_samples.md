# Log Samples — SentinelShield

Captured on **2026-08-20** from the Docker-deployed proxy (172.19.0.1 is the
Docker bridge gateway IP).

---

## Allowed (normal request)

```json
{"timestamp": "2026-08-20T11:05:44.118587+00:00", "level": "INFO",
 "event": "access", "client_ip": "172.19.0.1", "method": "GET",
 "path": "/robots.txt", "status": 200, "elapsed_ms": 4.58}
```

---

## Blocked (attack request — three events per attack)

Detection event (which rule matched):

```json
{"timestamp": "2026-08-20T11:06:21.405310+00:00", "level": "WARNING",
 "event": "detection", "client_ip": "172.19.0.1", "path": "/",
 "attack_type": "sqli", "rule_id": "SQLI-001"}
```

Block decision event:

```json
{"timestamp": "2026-08-20T11:06:21.405502+00:00", "level": "WARNING",
 "event": "block", "client_ip": "172.19.0.1", "path": "/",
 "reason_type": "AttackDetected", "reason": "sqli: SQLI-001"}
```

Request result (HTTP 403 returned to the client):

```json
{"timestamp": "2026-08-20T11:06:21.405561+00:00", "level": "INFO",
 "event": "access", "client_ip": "172.19.0.1", "method": "GET",
 "path": "/", "status": 403, "elapsed_ms": 0.98}
```

---

## Rate limited (HTTP 429)

```json
{"timestamp": "2026-08-20T11:06:21.697095+00:00", "level": "INFO",
 "event": "access", "client_ip": "172.19.0.1", "method": "GET",
 "path": "/", "status": 429, "elapsed_ms": 0.11}
```
