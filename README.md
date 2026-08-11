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

## Run it on your laptop

### What you need

- Docker Desktop
- Git
- A terminal

### Steps

Clone the repository and go into the folder:

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

Check that the containers are running:

```bash
docker compose ps
```

The ports used are:

- `3000` - Juice Shop directly (bypasses SentinelShield)
- `8080` - Juice Shop through SentinelShield

Open the protected app here:

```text
http://localhost:8080
```

## Deploy it to Render

Juice Shop and SentinelShield are two different apps, so they need two separate services on Render. Do not try to run both from one service with two start commands.

The layout looks like this:

```text
Client
   |
   v
Sentinel Shield proxy
   |
   v  TARGET_URL
Juice Shop
```

### The easy way (use the blueprint)

The repository has a `render.yaml` file. On Render, go to **New → Blueprint**, pick this repository, and it creates both web services for you:

- `juice-shop` - the Juice Shop app
- `sentinel-shield-proxy` - the public proxy

After the blueprint runs, you still need to set `TARGET_URL` (see the next section), because the free plan does not let Render work out the Juice Shop URL automatically.

### The manual way

1. Create a Juice Shop service. Use the Docker image `bkimminich/juice-shop` (or the `juiceshop/Dockerfile` in this repo).
2. Create a Sentinel Shield service with the start command `sentinel-shield proxy`.
3. Add the `TARGET_URL` environment variable to the Sentinel Shield service.
4. Set `TARGET_URL` to the public URL of the Juice Shop service, for example:

   ```text
   https://juice-shop-4kr8.onrender.com
   ```

5. Sentinel Shield listens on `0.0.0.0:$PORT`, so it automatically uses the port Render gives it. The health check path is `/healthz`.

### Important: do not use localhost:3000

Do not set `TARGET_URL` to `http://localhost:3000`. On Render, `localhost` means the inside of the Sentinel Shield container itself, and there is nothing running there. So the proxy would try to forward requests to itself and fail.

I also tried using Render's internal service name (like `juice-shop:10000`), but that did not work on the free plan either. The public URL of the Juice Shop service is the reliable option.

## Use it online

The live version of the project is:

```text
https://sentinel-shield-proxy.onrender.com
```

Open that link in a browser and you should see the Juice Shop app, but every request goes through SentinelShield first.

### Test normal traffic

```bash
curl -i https://sentinel-shield-proxy.onrender.com/
```

A normal request should be forwarded and come back with a successful response from Juice Shop.

### Test detection (SQL injection)

```bash
curl -G -i \
  --data-urlencode "q=' OR '1'='1" \
  https://sentinel-shield-proxy.onrender.com/rest/products/search
```

### Test detection (XSS)

```bash
curl -G -i \
  --data-urlencode "q=<script>alert(1)</script>" \
  https://sentinel-shield-proxy.onrender.com/rest/products/search
```

A blocked request should come back something like:

```text
HTTP/1.1 403 Forbidden
X-SentinelShield: blocked
```

The response body contains the reason for the block.

### Test rate limiting

The rate limiter allows 50 requests per minute with a burst of 20. This loop sends 25 requests quickly:

```bash
for i in {1..25}; do
  curl -s -o /dev/null -w "request=$i status=%{http_code}\n" \
    -G \
    --data-urlencode 'q=test' \
    https://sentinel-shield-proxy.onrender.com/rest/products/search
done
```

After the burst is used up, some requests should return `429`. The exact number can change if tokens refill during the test.

The same test commands work locally too, just replace the URL with `http://localhost:8080`.

## View logs

To watch the proxy logs on your laptop:

```bash
docker compose logs -f sentinel-shield
```

On Render, open the `sentinel-shield-proxy` service and go to the **Logs** tab.

The logs show normal access, detected attacks, blocks, and rate-limit events. There are also saved example logs in the `evidence/` folder.

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

Detailed project report:

```text
[Add your public report link here]
```

Project feedback video:

```text
[Add your video link here]
```

## What I learned

This project taught me how a reverse proxy can sit in front of a web app and check requests before they reach it. I learned about rule matching, rate limiting, JSON logging, Docker networking, false positives, and why it is important to test normal traffic as well as attack traffic. I also learned how to deploy two separate services to Render and connect them with an environment variable.

## License

This project is for educational and practical use. Add a license here if one is required by your institution or project rules.
