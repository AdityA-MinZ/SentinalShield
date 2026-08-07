import time
from typing import Optional, Callable

from .config import Config, config as default_config
from .exceptions import AttackDetected, BlockedIP, RateLimitExceeded
from ..detection.rules_engine import RulesEngine
from ..protection.rate_limiter import RateLimiter
from ..protection.ip_reputation import IPReputation
from ..protection.sanitizer import Sanitizer
from ..monitor.traffic_analyzer import TrafficAnalyzer
from ..monitor.logger import Logger


class SentinelShield:
    def __init__(self, app: Callable, config: Optional[Config] = None):
        self.app = app
        self.config = config or default_config
        self.rules_engine = RulesEngine(self.config.rules_dir)
        self.rate_limiter = RateLimiter(self.config.rate_limiter)
        self.ip_reputation = IPReputation(self.config.ip_reputation)
        self.sanitizer = Sanitizer()
        self.traffic_analyzer = TrafficAnalyzer(self.config.traffic_analyzer)
        self.logger = Logger(self.config.logging)

        self.detection_mode = self.config.detection.get("mode", "log")

    def __call__(self, environ, start_response):
        start_time = time.monotonic()
        client_ip = environ.get("REMOTE_ADDR", "unknown")
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "/")

        try:
            self._check_ip_reputation(client_ip)
            self._check_rate_limit(client_ip)
            self._inspect_request(environ, client_ip)
            self.traffic_analyzer.record(method, path, 200)

            def custom_start_response(status, headers, exc_info=None):
                self.traffic_analyzer.record(
                    method, path, int(status.split()[0])
                )
                return start_response(status, headers, exc_info)

            return self.app(environ, custom_start_response)

        except (AttackDetected, BlockedIP, RateLimitExceeded) as e:
            self.logger.log_block(client_ip, path, type(e).__name__, str(e))
            status = 429 if isinstance(e, RateLimitExceeded) else 403
            self.traffic_analyzer.record(method, path, status)
            return self._block_response(start_response, str(e), status)

        except Exception as e:
            self.logger.log_error(client_ip, path, str(e))
            self.traffic_analyzer.record(method, path, 500)
            return self._error_response(start_response)

        finally:
            elapsed = time.monotonic() - start_time
            self.logger.log_access(
                client_ip, method, path,
                self.traffic_analyzer.get_status_code() or 200,
                elapsed
            )

    def _check_ip_reputation(self, client_ip: str):
        if not self.ip_reputation.is_allowed(client_ip):
            raise BlockedIP(client_ip, "IP is blocked")

    def _check_rate_limit(self, client_ip: str):
        if self.ip_reputation.is_allowlisted(client_ip):
            return
        if not self.rate_limiter.allow(client_ip):
            raise RateLimitExceeded(client_ip)

    def _inspect_request(self, environ, client_ip: str):
        request = self._parse_wsgi_request(environ)
        matches = self.rules_engine.evaluate(request)
        for match in matches:
            if self.detection_mode == "block":
                raise AttackDetected(
                    rule_id=match["rule_id"],
                    attack_type=match["attack_type"],
                    confidence=match["confidence"],
                    client_ip=client_ip,
                    location=match["location"],
                    payload=match["payload"],
                )
            self.logger.log_warning(
                client_ip, request["path"],
                match["attack_type"], match["rule_id"]
            )

    def _parse_wsgi_request(self, environ: dict) -> dict:
        query_string = environ.get("QUERY_STRING", "")
        body = self._read_wsgi_body(environ)
        headers = {
            k[5:].replace("_", "-").lower(): v
            for k, v in environ.items()
            if k.startswith("HTTP_")
        }
        content_type = environ.get("CONTENT_TYPE", "")
        cookies = environ.get("HTTP_COOKIE", "")
        return {
            "method": environ.get("REQUEST_METHOD", "GET"),
            "path": environ.get("PATH_INFO", "/"),
            "query": query_string,
            "body": body,
            "headers": headers,
            "content_type": content_type,
            "cookies": cookies,
            "uri": environ.get("RAW_URI", ""),
        }

    def _read_wsgi_body(self, environ: dict) -> str:
        try:
            length = int(environ.get("CONTENT_LENGTH", 0))
            if length > 0:
                body = environ["wsgi.input"].read(length)
                return body.decode("utf-8", errors="replace")
        except (ValueError, KeyError):
            pass
        return ""

    def _block_response(self, start_response, reason: str, status: int = 403):
        phrase = "429 Too Many Requests" if status == 429 else "403 Forbidden"
        headers = [
            ("Content-Type", "application/json"),
            ("X-SentinelShield", "blocked"),
        ]
        body = f'{{"error":"blocked","reason":"{reason}"}}'
        start_response(phrase, headers)
        return [body.encode()]

    def _error_response(self, start_response):
        headers = [("Content-Type", "application/json")]
        body = '{"error":"internal_error"}'
        start_response("500 Internal Server Error", headers)
        return [body.encode()]
