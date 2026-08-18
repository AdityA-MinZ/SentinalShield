"""
The reverse proxy used in front of non-Python apps (like OWASP Juice Shop).

It runs the same checks as the WSGI middleware (blocked IP, rate limit,
attack rules) and then forwards clean requests to the upstream server.
"""

import os
import time

import aiohttp
from aiohttp import web
from multidict import CIMultiDict

from ..core.utils import get_client_ip_from_headers
from ..detection.rules_engine import RulesEngine
from ..monitor.logger import Logger
from ..monitor.traffic_analyzer import TrafficAnalyzer
from ..protection.ip_reputation import IPReputation
from ..protection.rate_limiter import RateLimiter


_STATIC_EXTENSIONS = frozenset({
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
})


class ProxyServer:
    def __init__(self, config):
        self.config = config
        self.upstream = config.server.get("upstream", "http://localhost:3000")
        self.rules_engine = RulesEngine(config.rules_dir)
        self.rate_limiter = RateLimiter(config.rate_limiter)
        self.ip_reputation = IPReputation(config.ip_reputation)
        self.traffic_analyzer = TrafficAnalyzer(config.traffic_analyzer)
        self.logger = Logger(config.logging)
        self.detection_mode = config.detection.get("mode", "log")
        self.app = None

    def build_app(self):
        """Build the aiohttp app. Every path goes through _handle_request."""
        self.app = web.Application()
        self.app.router.add_route("*", "/{tail:.*}", self._handle_request)
        return self.app

    async def _handle_request(self, request):
        lower_headers = {k.lower(): v for k, v in request.headers.items()}
        client_ip = get_client_ip_from_headers(lower_headers, request.remote or "127.0.0.1")
        method = request.method
        path = request.path
        start_time = time.monotonic()
        status_code = 200

        try:
            # 0) Health check for Render.
            if path == "/healthz":
                return web.Response(status=200, body=b'{"status":"ok"}')

            # 1) Blocked IP?
            if not self.ip_reputation.is_allowed(client_ip):
                self.logger.log_block(client_ip, path, "BlockedIP", "IP is blocked")
                status_code = 403
                return web.Response(status=403, body=b'{"error":"blocked"}')

            # 2) Too many requests?  Static assets are exempt.
            ext = os.path.splitext(path)[1].lower()
            if ext not in _STATIC_EXTENSIONS and not self.ip_reputation.is_allowlisted(client_ip) and not self.rate_limiter.allow(client_ip):
                self.logger.log_block(client_ip, path, "RateLimitExceeded", "Rate limit exceeded")
                status_code = 429
                return web.Response(status=429, body=b'{"error":"rate_limited"}')

            # 3) Attack pattern?
            body = await request.read() if request.can_read_body else b""
            request_data = self._build_request(request, body)
            matches = self.rules_engine.evaluate(request_data)

            if matches:
                for match in matches:
                    self.logger.log_warning(client_ip, path, match["attack_type"], match["rule_id"])
                    self.traffic_analyzer.record_attack(match["attack_type"])

                if self.detection_mode == "block":
                    first_match = matches[0]
                    self.logger.log_block(
                        client_ip, path, "AttackDetected",
                        f"{first_match['attack_type']}: {first_match['rule_id']}",
                    )
                    status_code = 403
                    return web.Response(
                        status=403,
                        body=b'{"error":"blocked","reason":"attack_detected"}',
                        headers={"X-SentinelShield": "blocked"},
                    )

            # 4) Forward the request to the upstream server.
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.request(
                        method=method,
                        url=f"{self.upstream}{path}",
                        params=request.query,
                        headers=self._clean_headers(request),
                        data=body,
                        timeout=aiohttp.ClientTimeout(total=30),
                    ) as response:
                        response_body = await response.read()
                        status_code = response.status
                        self.traffic_analyzer.record(method, path, response.status)
                        return web.Response(
                            body=response_body,
                            status=response.status,
                            headers=self._clean_response_headers(response),
                        )
            except Exception as error:
                self.logger.log_error(client_ip, path, str(error))
                status_code = 502
                return web.Response(
                    status=502,
                    body=f'{{"error":"upstream_unavailable","detail":"{str(error)}"}}'.encode(),
                )

        finally:
            elapsed = time.monotonic() - start_time
            self.logger.log_access(client_ip, method, path, status_code, elapsed)

    def _build_request(self, request, body):
        """Build the dict the rules engine scans from an aiohttp request."""
        skip = {"referer", "origin"}  # the site's own headers trigger false positives
        headers = {}
        for key, value in request.headers.items():
            if key.lower() not in skip:
                headers[key.lower()] = value
        return {
            "method": request.method,
            "path": request.path,
            "query": request.query_string,
            "body": body.decode("utf-8", errors="replace"),
            "headers": headers,
            "content_type": request.content_type or "",
            "cookies": request.headers.get("Cookie", ""),
            "uri": f"{request.path}?{request.query_string}",
        }

    def _clean_headers(self, request):
        """Remove hop-by-hop headers before forwarding to the upstream."""
        skip = {
            "host", "connection", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailers",
            "transfer-encoding", "upgrade", "accept-encoding",
        }
        clean = {}
        for key, value in request.headers.items():
            if key.lower() not in skip:
                clean[key] = value
        return clean

    def _clean_response_headers(self, response):
        """Remove hop-by-hop headers from the upstream response."""
        skip = {
            "connection", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailers",
            "transfer-encoding", "upgrade",
        }
        clean = CIMultiDict()
        for key, value in response.headers.items():
            if key.lower() not in skip:
                clean.add(key, value)
        return clean

    async def start(self):
        host = self.config.server.get("host", "0.0.0.0")
        port = self.config.server.get("port", 8080)
        runner = web.AppRunner(self.build_app())
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        await site.start()
        print(f"SentinelShield proxy on {host}:{port} -> {self.upstream}")
        if self.upstream == "http://localhost:3000" and not os.environ.get("TARGET_URL"):
            print(
                "WARNING: forwarding to http://localhost:3000. On Render that is the "
                "proxy's own container, not Juice Shop. Set the TARGET_URL env var to "
                "the Juice Shop service URL."
            )
        return runner
