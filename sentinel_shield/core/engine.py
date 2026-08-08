import time
from typing import Callable, Optional

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
        t0 = time.monotonic()
        ip = environ.get("REMOTE_ADDR", "unknown")
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "/")

        try:
            self._check_ip(ip)
            self._check_rate(ip)
            self._inspect(environ, ip)
            self.traffic_analyzer.record(method, path, 200)

            def custom_start_response(status, headers, exc_info=None):
                self.traffic_analyzer.record(method, path, int(status.split()[0]))
                return start_response(status, headers, exc_info)

            return self.app(environ, custom_start_response)

        except (AttackDetected, BlockedIP, RateLimitExceeded) as e:
            self.logger.log_block(ip, path, type(e).__name__, str(e))
            status = 429 if isinstance(e, RateLimitExceeded) else 403
            self.traffic_analyzer.record(method, path, status)
            return self._block(start_response, str(e), status)

        except Exception as e:
            self.logger.log_error(ip, path, str(e))
            self.traffic_analyzer.record(method, path, 500)
            return self._error(start_response)

        finally:
            elapsed = time.monotonic() - t0
            self.logger.log_access(
                ip, method, path,
                self.traffic_analyzer.get_status_code() or 200,
                elapsed,
            )

    def _check_ip(self, ip):
        if not self.ip_reputation.is_allowed(ip):
            raise BlockedIP(ip, "IP is blocked")

    def _check_rate(self, ip):
        if self.ip_reputation.is_allowlisted(ip):
            return
        if not self.rate_limiter.allow(ip):
            raise RateLimitExceeded(ip)

    def _inspect(self, environ, ip):
        req = self._parse_req(environ)
        matches = self.rules_engine.evaluate(req)
        for m in matches:
            if self.detection_mode == "block":
                raise AttackDetected(
                    rule_id=m["rule_id"],
                    attack_type=m["attack_type"],
                    confidence=m["confidence"],
                    client_ip=ip,
                    location=m["location"],
                    payload=m["payload"],
                )
            self.logger.log_warning(ip, req["path"], m["attack_type"], m["rule_id"])

    def _parse_req(self, environ):
        headers = {}
        for k, v in environ.items():
            if k.startswith("HTTP_"):
                headers[k[5:].replace("_", "-").lower()] = v
        return {
            "method": environ.get("REQUEST_METHOD", "GET"),
            "path": environ.get("PATH_INFO", "/"),
            "query": environ.get("QUERY_STRING", ""),
            "body": self._read_body(environ),
            "headers": headers,
            "content_type": environ.get("CONTENT_TYPE", ""),
            "cookies": environ.get("HTTP_COOKIE", ""),
            "uri": environ.get("RAW_URI", ""),
        }

    def _read_body(self, environ):
        try:
            length = int(environ.get("CONTENT_LENGTH", 0))
            if length > 0:
                body = environ["wsgi.input"].read(length)
                return body.decode("utf-8", errors="replace")
        except (ValueError, KeyError):
            pass
        return ""

    def _block(self, start_response, reason, status=403):
        phrase = "429 Too Many Requests" if status == 429 else "403 Forbidden"
        headers = [
            ("Content-Type", "application/json"),
            ("X-SentinelShield", "blocked"),
        ]
        body = f'{{"error":"blocked","reason":"{reason}"}}'
        start_response(phrase, headers)
        return [body.encode()]

    def _error(self, start_response):
        headers = [("Content-Type", "application/json")]
        body = '{"error":"internal_error"}'
        start_response("500 Internal Server Error", headers)
        return [body.encode()]
