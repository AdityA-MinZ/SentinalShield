"""
The WSGI middleware that runs SentinelShield for a normal Python web app.

Every request goes through the same pipeline:
    1. Is the client IP blocked?
    2. Has the client hit the rate limit?
    3. Does the request match an attack rule?
If the request passes all checks it is forwarded to the real app.
"""

import time

from ..detection.rules_engine import RulesEngine
from ..monitor.logger import Logger
from ..monitor.traffic_analyzer import TrafficAnalyzer
from ..protection.ip_reputation import IPReputation
from ..protection.rate_limiter import RateLimiter
from ..protection.sanitizer import Sanitizer
from .config import config as default_config
from .exceptions import AttackDetected, BlockedIP, RateLimitExceeded
from .utils import get_client_ip_from_headers


class SentinelShield:
    def __init__(self, app, config=None):
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
        forwarded = {
            k[5:].replace("_", "-").lower(): v
            for k, v in environ.items()
            if k.startswith("HTTP_")
        }
        client_ip = get_client_ip_from_headers(forwarded, environ.get("REMOTE_ADDR", "unknown"))
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "/")
        status_code = 200

        def remember_status(status_line, headers, exc_info=None):
            # Capture the status the real app picked, so the log line below
            # and the traffic stats record the true result of the request.
            nonlocal status_code
            status_code = int(status_line.split()[0])
            self.traffic_analyzer.record(method, path, status_code)
            return start_response(status_line, headers, exc_info)

        try:
            self._check_ip(client_ip)
            self._check_rate(client_ip)
            self._inspect(environ, client_ip)
            return self.app(environ, remember_status)

        except (AttackDetected, BlockedIP, RateLimitExceeded) as error:
            status_code = 429 if isinstance(error, RateLimitExceeded) else 403
            self.traffic_analyzer.record(method, path, status_code)
            self.logger.log_block(client_ip, path, type(error).__name__, str(error))
            return self._block_response(start_response, str(error), status_code)

        except Exception as error:
            status_code = 500
            self.traffic_analyzer.record(method, path, status_code)
            self.logger.log_error(client_ip, path, str(error))
            return self._error_response(start_response)

        finally:
            elapsed = time.monotonic() - start_time
            self.logger.log_access(client_ip, method, path, status_code, elapsed)

    def _check_ip(self, client_ip):
        """Reject the request if the IP is on the blocklist."""
        if not self.ip_reputation.is_allowed(client_ip):
            raise BlockedIP(client_ip, "IP is blocked")

    def _check_rate(self, client_ip):
        """Reject the request if the client used up its token bucket."""
        if self.ip_reputation.is_allowlisted(client_ip):
            return  # allowlisted IPs skip rate limiting
        if not self.rate_limiter.allow(client_ip):
            raise RateLimitExceeded(client_ip)

    def _inspect(self, environ, client_ip):
        """Scan the request against every rule."""
        request = self._parse_request(environ)
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
            # In "log" mode we only record the match, we do not block.
            self.logger.log_warning(client_ip, request["path"], match["attack_type"], match["rule_id"])

    def _parse_request(self, environ):
        """Turn a WSGI environ into a simple dict the rules engine can scan."""
        headers = {}
        for key, value in environ.items():
            if key.startswith("HTTP_"):
                # "HTTP_USER_AGENT" becomes "user-agent".
                headers[key[5:].replace("_", "-").lower()] = value

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
        """Read and decode the request body if there is one."""
        try:
            length = int(environ.get("CONTENT_LENGTH", 0))
            if length > 0:
                body = environ["wsgi.input"].read(length)
                return body.decode("utf-8", errors="replace")
        except (ValueError, KeyError):
            pass
        return ""

    def _block_response(self, start_response, reason, status_code):
        """Return a JSON 403/429 response instead of forwarding the request."""
        phrase = "429 Too Many Requests" if status_code == 429 else "403 Forbidden"
        headers = [
            ("Content-Type", "application/json"),
            ("X-SentinelShield", "blocked"),
        ]
        body = f'{{"error":"blocked","reason":"{reason}"}}'
        start_response(phrase, headers)
        return [body.encode()]

    def _error_response(self, start_response):
        """Return a generic JSON 500 response on unexpected errors."""
        headers = [("Content-Type", "application/json")]
        body = '{"error":"internal_error"}'
        start_response("500 Internal Server Error", headers)
        return [body.encode()]
