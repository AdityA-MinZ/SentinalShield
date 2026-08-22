# Log Analysis Report

| Time | IP | Method | Path | Status | Result | Attack | Rule |
|------|----|--------|------|--------|--------|--------|------|
| 11:05:42 | 172.19.0.1 | GET | /api/categories | 500 | ALLOWED |  |  |
| 11:05:44 | 172.19.0.1 | GET | /robots.txt | 200 | ALLOWED |  |  |
| 11:05:45 | 172.19.0.1 | GET | /api/products | 200 | ALLOWED |  |  |
| 11:05:47 | 172.19.0.1 | GET | /robots.txt | 200 | ALLOWED |  |  |
| 11:05:49 | 172.19.0.1 | GET | /products | 200 | ALLOWED |  |  |
| 11:05:51 | 172.19.0.1 | GET | /privacy | 200 | ALLOWED |  |  |
| 11:05:53 | 172.19.0.1 | GET | /contact | 200 | ALLOWED |  |  |
| 11:05:54 | 172.19.0.1 | GET | /sitemap.xml | 200 | ALLOWED |  |  |
| 11:05:56 | 172.19.0.1 | GET | /images/logo.png | 200 | ALLOWED |  |  |
| 11:05:58 | 172.19.0.1 | GET | /products | 200 | ALLOWED |  |  |
| 11:06:00 | 172.19.0.1 | GET | /search | 200 | ALLOWED |  |  |
| 11:06:02 | 172.19.0.1 | GET | /assets/style.css | 200 | ALLOWED |  |  |
| 11:06:04 | 172.19.0.1 | GET | /robots.txt | 200 | ALLOWED |  |  |
| 11:06:05 | 172.19.0.1 | GET | /about | 200 | ALLOWED |  |  |
| 11:06:07 | 172.19.0.1 | GET | /support | 200 | ALLOWED |  |  |
| 11:06:21 | 172.19.0.1 | GET | / | 403 | BLOCKED | sqli | SQLI-001 |
| 11:06:21 | 172.19.0.1 | GET | / | 403 | BLOCKED | sqli | SQLI-002 |
| 11:06:21 | 172.19.0.1 | GET | / | 403 | BLOCKED | sqli | SQLI-002 |
| 11:06:21 | 172.19.0.1 | GET | / | 403 | BLOCKED | sqli | SQLI-003 |
| 11:06:21 | 172.19.0.1 | GET | / | 403 | BLOCKED | sqli | SQLI-005 |
| 11:06:21 | 172.19.0.1 | GET | / | 403 | BLOCKED | xss | XSS-001 |
| 11:06:21 | 172.19.0.1 | GET | / | 403 | BLOCKED | xss | XSS-002 |
| 11:06:21 | 172.19.0.1 | GET | / | 403 | BLOCKED | xss | XSS-003 |
| 11:06:21 | 172.19.0.1 | GET | / | 403 | BLOCKED | xss | XSS-001 |
| 11:06:21 | 172.19.0.1 | GET | / | 403 | BLOCKED | xss | XSS-002 |
| 11:06:21 | 172.19.0.1 | GET | / | 403 | BLOCKED | lfi | LFI-001 |
| 11:06:21 | 172.19.0.1 | GET | / | 403 | BLOCKED | lfi | LFI-002 |
| 11:06:21 | 172.19.0.1 | GET | / | 403 | BLOCKED | lfi | LFI-004 |
| 11:06:21 | 172.19.0.1 | GET | / | 403 | BLOCKED | lfi | LFI-005 |
| 11:06:21 | 172.19.0.1 | GET | / | 403 | BLOCKED | lfi | LFI-003 |
| 11:06:21 | 172.19.0.1 | GET | / | 403 | BLOCKED | ssrf | SSRF-001 |
| 11:06:21 | 172.19.0.1 | GET | / | 403 | BLOCKED | ssrf | SSRF-001 |
| 11:06:21 | 172.19.0.1 | GET | / | 403 | BLOCKED | ssrf | SSRF-001 |
| 11:06:21 | 172.19.0.1 | GET | / | 403 | BLOCKED | ssrf | SSRF-001 |
| 11:06:21 | 172.19.0.1 | GET | / | 403 | BLOCKED | lfi | LFI-001 |
| 11:06:21 | 172.19.0.1 | GET | / | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:06:21 | 172.19.0.1 | GET | / | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:06:21 | 172.19.0.1 | GET | / | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:06:21 | 172.19.0.1 | GET | / | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:06:21 | 172.19.0.1 | GET | / | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:06:21 | 172.19.0.1 | GET | / | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:06:21 | 172.19.0.1 | GET | / | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:06:21 | 172.19.0.1 | GET | / | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:06:21 | 172.19.0.1 | GET | / | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:06:21 | 172.19.0.1 | GET | / | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:06:21 | 172.19.0.1 | GET | / | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:06:21 | 172.19.0.1 | GET | / | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:06:21 | 172.19.0.1 | GET | /about | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:08:51 | 172.19.0.1 | GET | /login | 200 | ALLOWED |  |  |
| 11:08:51 | 172.19.0.1 | GET | /login | 200 | ALLOWED |  |  |
| 11:08:51 | 172.19.0.1 | GET | /login | 200 | ALLOWED |  |  |
| 11:08:51 | 172.19.0.1 | GET | /login | 200 | ALLOWED |  |  |
| 11:08:51 | 172.19.0.1 | GET | /login | 200 | ALLOWED |  |  |
| 11:08:51 | 172.19.0.1 | GET | /login | 200 | ALLOWED |  |  |
| 11:08:51 | 172.19.0.1 | GET | /login | 200 | ALLOWED |  |  |
| 11:08:51 | 172.19.0.1 | GET | /login | 200 | ALLOWED |  |  |
| 11:08:51 | 172.19.0.1 | GET | /login | 200 | ALLOWED |  |  |
| 11:08:51 | 172.19.0.1 | GET | /login | 200 | ALLOWED |  |  |
| 11:08:51 | 172.19.0.1 | GET | /login | 200 | ALLOWED |  |  |
| 11:08:51 | 172.19.0.1 | GET | /login | 200 | ALLOWED |  |  |
| 11:08:52 | 172.19.0.1 | GET | /login | 200 | ALLOWED |  |  |
| 11:08:52 | 172.19.0.1 | GET | /login | 200 | ALLOWED |  |  |
| 11:08:52 | 172.19.0.1 | GET | /login | 200 | ALLOWED |  |  |
| 11:08:52 | 172.19.0.1 | GET | /login | 200 | ALLOWED |  |  |
| 11:08:52 | 172.19.0.1 | GET | /login | 200 | ALLOWED |  |  |
| 11:08:52 | 172.19.0.1 | GET | /login | 200 | ALLOWED |  |  |
| 11:08:52 | 172.19.0.1 | GET | /login | 200 | ALLOWED |  |  |
| 11:08:52 | 172.19.0.1 | GET | /login | 200 | ALLOWED |  |  |
| 11:08:52 | 172.19.0.1 | GET | /login | 200 | ALLOWED |  |  |
| 11:08:52 | 172.19.0.1 | GET | /login | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:08:52 | 172.19.0.1 | GET | /login | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:08:53 | 172.19.0.1 | GET | /login | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:08:53 | 172.19.0.1 | GET | /login | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:08:53 | 172.19.0.1 | GET | /login | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:08:53 | 172.19.0.1 | GET | /login | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:08:53 | 172.19.0.1 | GET | /login | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:08:53 | 172.19.0.1 | GET | /login | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:08:53 | 172.19.0.1 | GET | /login | 200 | ALLOWED |  |  |
| 11:08:53 | 172.19.0.1 | GET | /login | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:08:53 | 172.19.0.1 | GET | /login | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:08:53 | 172.19.0.1 | GET | /login | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:08:53 | 172.19.0.1 | GET | /login | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:08:53 | 172.19.0.1 | GET | /login | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:08:53 | 172.19.0.1 | GET | /login | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:08:53 | 172.19.0.1 | GET | /login | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:08:54 | 172.19.0.1 | GET | /login | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:08:54 | 172.19.0.1 | GET | /login | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |
| 11:08:54 | 172.19.0.1 | GET | /login | 429 | RATE LIMITED | rate_limit | RateLimitExceeded |

## Summary

- **Total requests:** 88
- **Allowed:** 37
- **Blocked:** 20
- **Rate limited:** 31

## Attacks by Category

| Category | Count |
|----------|-------|
| lfi | 6 |
| sqli | 5 |
| ssrf | 4 |
| xss | 5 |

## Top IPs

| IP | Requests |
|----|----------|
| 172.19.0.1 | 88 |
