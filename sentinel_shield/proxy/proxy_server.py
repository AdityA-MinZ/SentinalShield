import asyncio
import time
from typing import Optional, Tuple

import aiohttp
from aiohttp import web

from ..core.config import Config
from ..core.engine import SentinelShield
from ..detection.rules_engine import RulesEngine
from ..protection.rate_limiter import RateLimiter
from ..protection.ip_reputation import IPReputation
from ..monitor.traffic_analyzer import TrafficAnalyzer
from ..monitor.logger import Logger


class ProxyServer:
    def __init__(self, config: Config):
        self.config = config
        self.upstream = config.server.get("upstream", "http://localhost:3000")
        self.rules_engine = RulesEngine(config.rules_dir)
        self.rate_limiter = RateLimiter(config.rate_limiter)
        self.ip_reputation = IPReputation(config.ip_reputation)
        self.traffic_analyzer = TrafficAnalyzer(config.traffic_analyzer)
        self.logger = Logger(config.logging)
        self.detection_mode = config.detection.get("mode", "log")
        self.app = None

    def build_app(self) -> web.Application:
        self.app = web.Application()
        self.app.router.add_route("*", "/{tail:.*}", self._handle_request)
        return self.app

    async def _handle_request(self, request: web.Request):
        client_ip = request.remote or "127.0.0.1"
        method = request.method
        path = request.path
        start_time = time.monotonic()
        status = {"code": 200}

        try:
            if not self.ip_reputation.is_allowed(client_ip):
                self.logger.log_block(client_ip, path, "BlockedIP",
                                      "IP is blocked")
                status["code"] = 403
                return web.Response(status=403, body=b'{"error":"blocked"}')

            if not self.ip_reputation.is_allowlisted(client_ip) and \
                    not self.rate_limiter.allow(client_ip):
                self.logger.log_block(client_ip, path, "RateLimitExceeded",
                                      "Rate limit exceeded")
                status["code"] = 429
                return web.Response(
                    status=429, body=b'{"error":"rate_limited"}'
                )

            body = await request.read() if request.can_read_body else b""
            req_data = self._build_request_data(request, body)
            matches = self.rules_engine.evaluate(req_data)

            if matches:
                for match in matches:
                    self.logger.log_warning(
                        client_ip, path, match["attack_type"], match["rule_id"]
                    )
                    self.traffic_analyzer.record_attack(match["attack_type"])

                if self.detection_mode == "block":
                    self.logger.log_block(
                        client_ip, path, "AttackDetected",
                        f"{matches[0]['attack_type']}: {matches[0]['rule_id']}"
                    )
                    status["code"] = 403
                    return web.Response(
                        status=403,
                        body=b'{"error":"blocked","reason":"attack_detected"}',
                        headers={"X-SentinelShield": "blocked"},
                    )

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.request(
                        method=method,
                        url=f"{self.upstream}{path}",
                        params=request.query,
                        headers=self._clean_headers(request),
                        data=body,
                        timeout=aiohttp.ClientTimeout(total=30),
                    ) as upstream_resp:
                        resp_body = await upstream_resp.read()
                        status["code"] = upstream_resp.status
                        self.traffic_analyzer.record(method, path,
                                                     upstream_resp.status)
                        return web.Response(
                            body=resp_body,
                            status=upstream_resp.status,
                            headers=dict(upstream_resp.headers),
                        )
            except Exception as e:
                self.logger.log_error(client_ip, path, str(e))
                status["code"] = 502
                return web.Response(
                    status=502,
                    body=f'{{"error":"upstream_unavailable","detail":"{str(e)}"}}'.encode(),
                )
        finally:
            elapsed = time.monotonic() - start_time
            self.logger.log_access(client_ip, method, path,
                                   status["code"], elapsed)

    def _build_request_data(self, request: web.Request,
                            body: bytes) -> dict:
        headers = {k.lower(): v for k, v in request.headers.items()}
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

    def _clean_headers(self, request: web.Request) -> dict:
        hop_by_hop = {
            "host", "connection", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailers",
            "transfer-encoding", "upgrade",
        }
        return {
            k: v for k, v in request.headers.items()
            if k.lower() not in hop_by_hop
        }

    async def start(self):
        host = self.config.server.get("host", "0.0.0.0")
        port = self.config.server.get("port", 8080)
        runner = web.AppRunner(self.build_app())
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        await site.start()
        print(f"SentinelShield proxy on {host}:{port} -> {self.upstream}")
        return runner
