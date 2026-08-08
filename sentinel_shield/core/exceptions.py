"""
The engine raises one of these exceptions to stop a request, and the WAF /
proxy turns it into an HTTP response (403 for attacks and blocked IPs,
429 for rate limiting).
"""


class SentinelShieldError(Exception):
    """Base class for all SentinelShield errors."""


class ConfigError(SentinelShieldError):
    """Raised when a config file is missing or invalid."""


class DetectionError(SentinelShieldError):
    """Raised when something goes wrong while inspecting a request."""


class RateLimitExceeded(SentinelShieldError):
    """Raised when a client has used up its request tokens."""

    def __init__(self, client_ip):
        self.client_ip = client_ip
        super().__init__(f"Rate limit exceeded for {client_ip}")


class BlockedIP(SentinelShieldError):
    """Raised when the client IP is on the blocklist."""

    def __init__(self, client_ip, reason=""):
        self.client_ip = client_ip
        self.reason = reason
        super().__init__(f"Blocked IP: {client_ip} - {reason}")


class AttackDetected(SentinelShieldError):
    """Raised when a rule matched and detection mode is "block"."""

    def __init__(self, rule_id, attack_type, confidence, client_ip,
                 location, payload):
        self.rule_id = rule_id
        self.attack_type = attack_type
        self.confidence = confidence
        self.client_ip = client_ip
        self.location = location
        self.payload = payload
        super().__init__(
            f"[{attack_type}] Rule {rule_id} matched for {client_ip} "
            f"at {location} (confidence: {confidence:.2f})"
        )
