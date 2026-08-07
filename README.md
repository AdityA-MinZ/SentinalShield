# SentinelShield

Advanced Intrusion Detection & Web Protection System — a rule-based Web Application Firewall (WAF) and Intrusion Detection System (IDS) built as a practical learning project.

SentinelShield inspects every HTTP request (URL, query, body, headers, cookies) against 44 attack signatures across 7 categories, enforces IP-based rate limiting, writes structured JSON logs, and visualizes events on a live dashboard.

## Features

- **Rule-based detection** — 44 rules across SQL Injection, XSS, LFI, SSRF, Path Traversal, File Upload, and OS Command Injection
- **Dual deployment modes** — WSGI middleware to wrap an existing Python app, or a standalone async reverse proxy (`aiohttp`)
- **Behavior monitoring** — token-bucket rate limiting per IP with configurable thresholds and burst size
- **IP reputation** — allowlist / blocklist access control, mutable at runtime via the admin API
- **Structured logging** — JSONL access, block, and detection events for analysis
- **Live dashboard** — Flask + Chart.js visualization of attack types, timeline, top paths, and status codes
- **Admin REST API** — FastAPI endpoints for stats, rules, config, IP management, and rule hot-reload
- **CLI tool** — status, rule listing, report generation, proxy, dashboard, and admin servers
- **Docker deployment** — drop-in reverse proxy in front of OWASP Juice Shop

## Architecture

```
   Client ──► SentinelShield ──► Upstream App
                  │
   ┌──────────────┼──────────────────────┐
   │  1. IP Reputation  (allow/block)    │
   │  2. Rate Limiter    (token bucket)  │
   │  3. Rules Engine    (44 signatures) │
   │  4. Traffic Analyzer (sliding window)│
   │  5. Logger          (JSONL)         │
   └──────────────┼──────────────────────┘
                  ▼
        Dashboard / Admin API / Report
```

## Quickstart

Requires Python 3.9+.

```bash
# 1. Install
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt -e .

# 2. Check status
sentinel-shield status

# 3. Run the reverse proxy (upstream = OWASP Juice Shop, or any target)
sentinel-shield proxy --upstream http://localhost:3000 --port 8080

# 4. In another terminal: exercise the system
./scripts/test_attacks.sh            # simulated attacks (expect 403/429)
./scripts/normal_traffic.sh          # baseline legitimate traffic
./scripts/brute_force.sh             # rate-limit demo

# 5. Inspect results
sentinel-shield report --format table
sentinel-shield dashboard --port 9091   # http://localhost:9091
sentinel-shield admin --port 9090       # admin API at http://localhost:9090
```

## CLI Reference

| Command | Description |
|---|---|
| `sentinel-shield proxy` | Run the async reverse proxy |
| `sentinel-shield wrap` | Print WSGI integration instructions |
| `sentinel-shield admin` | Start the FastAPI admin API |
| `sentinel-shield dashboard` | Start the Flask dashboard |
| `sentinel-shield report` | Generate a security summary from the log |
| `sentinel-shield status` | Show system status |
| `sentinel-shield rules [RULE_ID]` | List rules or inspect one rule |

## Detection Rules

Rule definitions live in `sentinel_shield/detection/rules/*.yml` and are hot-reloadable:

| Category | Rules | Critical | High | Medium |
|---|---|---|---|---|
| SQL Injection | 8 | 5 | 3 | 0 |
| XSS | 8 | 2 | 5 | 1 |
| LFI | 6 | 3 | 3 | 0 |
| SSRF | 5 | 2 | 2 | 1 |
| Path Traversal | 4 | 1 | 3 | 0 |
| File Upload | 5 | 2 | 2 | 1 |
| Command Injection | 8 | 4 | 4 | 0 |
| **Total** | **44** | **19** | **22** | **3** |

## Configuration

All settings are in `sentinel-shield.yml` — detection mode (`block`/`log`), rate-limiter thresholds, IP allow/block lists, logging format, and traffic-analyzer window.

## Assignment Workflow

This project accompanies a structured student practical. See:

- `docs/student_worksheet.md` — step-by-step practical worksheet (architecture → rules → attack simulation → logs → dashboard → rate limiting)
- `docs/practical_work_report.md` — report template with sample outputs

## Tests

```bash
python -m pytest tests/ -v
```

## Docker

```bash
docker-compose up -d    # builds SentinelShield + OWASP Juice Shop
# SentinelShield: http://localhost:8080  (proxies to Juice Shop)
```

## Project Structure

```
sentinel_shield/
├── core/          # WSGI engine, config, exceptions
├── detection/     # rules engine + rules/*.yml signatures
├── protection/    # rate limiter, IP reputation, sanitizer, WAF adapter
├── monitor/       # JSON logger, traffic analyzer
├── api/           # FastAPI admin server
├── dashboard/     # Flask dashboard + Chart.js UI
├── proxy/         # aiohttp reverse proxy
└── cli/           # Click CLI
```

## License

MIT
