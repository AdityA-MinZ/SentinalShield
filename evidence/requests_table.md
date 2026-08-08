# Log Analysis Report

| Time | IP | Method | Path | Status | Result | Attack | Rule |
|------|----|--------|------|--------|--------|--------|------|
| 13:12:18 | 192.168.65.1 | GET | /cart | 200 | ALLOWED |  |  |
| 13:12:19 | 192.168.65.1 | GET | /products | 200 | ALLOWED |  |  |
| 13:12:20 | 192.168.65.1 | GET | /api/products | 200 | ALLOWED |  |  |
| 13:12:21 | 192.168.65.1 | GET | /privacy | 200 | ALLOWED |  |  |
| 13:12:22 | 192.168.65.1 | GET | /contact | 200 | ALLOWED |  |  |
| 13:12:23 | 192.168.65.1 | GET | /login | 200 | ALLOWED |  |  |
| 13:12:24 | 192.168.65.1 | GET | /about | 200 | ALLOWED |  |  |
| 13:12:25 | 192.168.65.1 | GET | /terms | 200 | ALLOWED |  |  |
| 13:12:25 | 192.168.65.1 | GET | /assets/style.css | 200 | ALLOWED |  |  |
| 13:12:26 | 192.168.65.1 | GET | /images/logo.png | 200 | ALLOWED |  |  |
| 13:12:27 | 192.168.65.1 | GET | /support | 200 | ALLOWED |  |  |
| 13:12:28 | 192.168.65.1 | GET | /images/logo.png | 200 | ALLOWED |  |  |
| 13:12:29 | 192.168.65.1 | GET | /terms | 200 | ALLOWED |  |  |
| 13:12:30 | 192.168.65.1 | GET | /assets/style.css | 200 | ALLOWED |  |  |
| 13:12:31 | 192.168.65.1 | GET | /assets/script.js | 200 | ALLOWED |  |  |
| 13:12:33 | 192.168.65.1 | GET | /socket.io/ | 200 | ALLOWED |  |  |
| 13:12:33 | 192.168.65.1 | POST | /socket.io/ | 200 | ALLOWED |  |  |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | sqli | SQLI-001 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | sqli | SQLI-002 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | sqli | SQLI-002 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | sqli | SQLI-003 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | sqli | SQLI-005 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | xss | XSS-001 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | xss | XSS-002 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | xss | XSS-003 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | xss | XSS-001 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | xss | XSS-002 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | lfi | LFI-001 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | lfi | LFI-002 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | lfi | LFI-004 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | lfi | LFI-005 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | lfi | LFI-003 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | ssrf | SSRF-001 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | ssrf | SSRF-001 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | ssrf | SSRF-001 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | ssrf | SSRF-001 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | lfi | LFI-001 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | lfi | LFI-001 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | command_injection | CMD-001 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | command_injection | CMD-004 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | command_injection | CMD-001 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | command_injection | CMD-001 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | command_injection | CMD-001 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | command_injection | CMD-004 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | command_injection | CMD-003 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | command_injection | CMD-003 |
| 13:12:35 | 192.168.65.1 | GET | / | 403 | BLOCKED | command_injection | CMD-002 |
| 13:12:35 | 192.168.65.1 | GET | / | 200 | ALLOWED |  |  |
| 13:12:35 | 192.168.65.1 | GET | / | 200 | ALLOWED |  |  |
| 13:12:35 | 192.168.65.1 | GET | /about | 200 | ALLOWED |  |  |

## Summary

- **Total requests:** 50
- **Allowed:** 20
- **Blocked:** 30
- **Rate limited:** 0

## Attacks by Category

| Category | Count |
|----------|-------|
| command_injection | 9 |
| lfi | 7 |
| sqli | 5 |
| ssrf | 4 |
| xss | 5 |

## Top IPs

| IP | Requests |
|----|----------|
| 192.168.65.1 | 50 |
