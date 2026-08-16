# SentinelShield

SentinelShield is a small web security project I built for a college assignment. It sits in front of a website and checks every request before letting it through. It is basically a basic Web Application Firewall (WAF) and a reverse proxy in one.

I used OWASP Juice Shop as the website behind it, because Juice Shop is a deliberately insecure app that is made for testing security tools.

## What it does

SentinelShield looks at each incoming request and:

- Detects suspicious requests (things that look like attacks).
- Blocks requests that match a security rule.
- Lets normal requests pass through to the app.
- Slows down users who send too many requests (rate limiting).
- Writes every request and security event to a JSON log.
- Shows useful details like the IP address, attack type, rule ID, status code, and time.

The rules it comes with cover examples of:

- SQL injection
- Cross-site scripting (XSS)
- Local file inclusion (LFI) and path traversal
- Server-side request forgery (SSRF)
- Command injection
- Suspicious file uploads

This is an educational project, not a production WAF. It should not be used to protect a real website without a lot more testing.

## How it works

```text
Browser or curl
       |
       v
SentinelShield proxy :8080
       |
       v
OWASP Juice Shop :3000
```

The proxy checks the request first. If the request looks normal, it forwards it to Juice Shop. If the request matches an attack rule, it returns a block response instead of forwarding it.

## Technologies used

- Python
- aiohttp (the proxy server)
- Docker and Docker Compose
- YAML for configuration
- Regular-expression based rules for detection
- JSONL logging
- OWASP Juice Shop for testing

## Project folders

```text
sentinel_shield/
├── api/          API and schemas
├── cli/          command-line commands
├── core/         common configuration and engine code
├── dashboard/   dashboard server and templates
├── detection/   detection engine and rules
├── monitor/     logging and traffic analysis
├── protection/  WAF, rate limiter, IP reputation, sanitizer
└── proxy/       reverse proxy server

evidence/        saved logs, reports, and summary tables
scripts/         test and traffic scripts
tests/           project tests
docs/            project documentation
```

## Practical results

During local testing, the project blocked test requests for SQL injection, XSS, LFI, SSRF, path traversal, and command injection. Normal control requests were allowed through.

The `evidence/` folder contains the logs and tables I used for the practical report, including:

- Attack request results.
- Normal traffic results.
- Blocked-request log samples.
- Rate-limit results.
- Summary tables.
- Practical report files.

These results are from the local test setup only. They are not a full security audit.

## Known limitations

- The rate limiter works in memory, so it is not shared between multiple instances.
- Docker networking can make several local requests look like they come from the same bridge IP.
- The rules are signature-based, so they can overlap or create false positives.
- Encoded payloads and unusual request formats need more testing.
- Juice Shop is intentionally insecure and should not be exposed publicly without proper access control.

## Links

Live deployment:

```text
https://sentinel-shield-proxy.onrender.com
```

Juice Shop service:

```text
https://juice-shop-4kr8.onrender.com
```

## What I learned

This project taught me how a reverse proxy can sit in front of a web app and check requests before they reach it. I learned about rule matching, rate limiting, JSON logging, Docker networking, false positives, and why it is important to test normal traffic as well as attack traffic. I also learned how to deploy two separate services to Render and connect them with an environment variable.
