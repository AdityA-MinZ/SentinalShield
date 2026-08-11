# SentinelShield

SentinelShield is a small web security project that works as a reverse proxy and a basic Web Application Firewall (WAF).

I made this project to understand how web requests can be checked before they reach an application. For the demo, I used OWASP Juice Shop as the application behind the proxy.

## What it does

SentinelShield checks incoming HTTP requests and can:

- Detect common suspicious requests.
- Block requests that match security rules.
- Allow normal requests to pass to the application.
- Apply rate limiting to repeated requests.
- Record request and security events in JSON logs.
- Show useful information such as the request IP, category, rule ID, status code, and time.

The current rules cover examples of:

- SQL injection
- Cross-site scripting (XSS)
- Local file inclusion and path traversal
- Server-side request forgery (SSRF)
- Command injection
- Suspicious file uploads

This is mainly an educational project and should not be treated as a production WAF without more testing.

## Basic architecture

```text
Browser or curl
       |
       v
SentinelShield proxy :8080
       |
       v
OWASP Juice Shop :3000
```

The proxy checks the request first. If it looks normal, it forwards the request to Juice Shop. If a rule is matched, it returns a block response instead of forwarding the request.

## Technologies used

- Python
- aiohttp
- Docker and Docker Compose
- YAML configuration
- Regular-expression based detection rules
- JSONL logging
- OWASP Juice Shop for testing

## Run the project

### Requirements

- Docker Desktop
- Git
- A terminal

### Start the containers

Clone the repository and enter the project directory:

```bash
git clone https://github.com/AdityA-MinZ/SentinalShield.git
cd SentinalShield
```

Start the project:

```bash
docker compose up --build
```

To run it in the background:

```bash
docker compose up -d --build
```

Check the containers:

```bash
docker compose ps
```

The normal setup uses these ports:

- `3000` - Juice Shop directly
- `8080` - Juice Shop through SentinelShield

Open the protected application here:

```text
http://localhost:8080
```

Opening `http://localhost:3000` bypasses SentinelShield and accesses Juice Shop directly.

## Deploying to Render

Juice Shop and Sentinel Shield are two separate apps, so they need two separate
Render services. Sentinel Shield is the proxy in front, and Juice Shop runs
behind it. Ideally Juice Shop would be a private service (no public URL), but
private services are not available on Render's free plan, so on a free plan
Juice Shop is also a public web service.

```text
Client
   |
   v
Sentinel Shield proxy
   |
   v  TARGET_URL
Juice Shop
```

The repo has a `render.yaml` file that creates both services as web services
and sets `TARGET_URL` automatically.

To deploy manually:

1. Create a Juice Shop service from the Docker image `bkimminich/juice-shop`.
2. Create a Sentinel Shield service with start command `sentinel-shield proxy`.
3. Set the `TARGET_URL` environment variable on Sentinel Shield to the Juice
   Shop URL, for example `https://your-juice-shop-service.onrender.com`.
4. Sentinel Shield listens on `0.0.0.0:$PORT`, so it uses the port that Render
   provides. The health check path is `/healthz`.

Do not set `TARGET_URL` to `http://localhost:3000`. On Render that address
points inside the Sentinel Shield container, not the Juice Shop service.

## View logs

To watch the proxy logs:

```bash
docker compose logs -f sentinel-shield
```

The logs contain information about normal access, detected attacks, blocks, and rate-limit events. The project also contains saved examples in the `evidence/` directory.

## Test normal traffic

```bash
curl -i http://localhost:8080/
```

A normal request should normally be forwarded and return a successful response from Juice Shop.

## Test detection

These tests are intended only for the local Juice Shop lab.

### SQL injection example

```bash
curl -G -i \\
  --data-urlencode "q=' OR '1'='1" \\
  http://localhost:8080/rest/products/search
```

### XSS example

```bash
curl -G -i \\
  --data-urlencode "q=<script>alert(1)</script>" \\
  http://localhost:8080/rest/products/search
```

A blocked request should return a response similar to:

```text
HTTP/1.1 403 Forbidden
X-SentinelShield: blocked
```

The response body contains the reason for the block.

## Test rate limiting

The rate limiter uses a token-bucket style approach. The current main configuration uses a rate limit of 50 requests per minute with a burst limit of 20.

Run a small local test:

```bash
for i in {1..25}; do
  curl -s -o /dev/null -w "request=$i status=%{http_code}\\n" \\
    -G \\
    --data-urlencode 'q=test' \\
    http://localhost:8080/rest/products/search
done
```

After the available burst is used, some requests should return HTTP `429` when rate limiting is reached. The exact number of successful requests can change if the browser has already used some tokens or if refill tokens arrive during the test.

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
docs/             project documentation
```

## Practical results

During the local testing, the project blocked test requests for SQL injection, XSS, LFI, SSRF, path traversal, and command injection. Normal control requests were allowed.

The evidence folder contains the detailed logs and tables used for the practical report, including:

- Attack request results.
- Normal traffic results.
- Blocked-request log samples.
- Rate-limit results.
- Summary tables.
- Practical report files.

The test results are for the local test setup and should not be interpreted as a complete security audit.

## Known limitations

- The rate limiter currently works in memory, so it is not shared between multiple application instances.
- Docker networking can make several local requests appear to come from the same bridge IP.
- Signature-based rules can sometimes overlap or create false positives.
- More testing is needed for encoded payloads and unusual request formats.
- Juice Shop is intentionally insecure and should not be exposed publicly without proper isolation and access control.

## Documentation and links

Detailed project report:

```text
[Add your public report link here]
```

Project deployment:

```text
[Add your public deployment link here]
```

Project feedback video:

```text
[Add your video link here]
```

## What I learned

This project helped me understand how a reverse proxy can be placed in front of a web application and how security checks can be applied before forwarding requests. I also learned about rule matching, rate limiting, JSON logging, Docker networking, false positives, and the importance of testing normal traffic as well as attack traffic.

## License

This project is for educational and practical use. Add a license here if one is required by your institution or project rules.
