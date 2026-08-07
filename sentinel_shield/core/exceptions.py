class SentinelShieldError(Exception):
    pass

class ConfigError(SentinelShieldError):
    pass

class DetectionError(SentinelShieldError):
    pass

class RateLimitExceeded(SentinelShieldError):
    def __init__(self, client_ip: str):
        self.client_ip = client_ip
        super().__init__(f"Rate limit exceeded for {client_ip}")

class BlockedIP(SentinelShieldError):
    def __init__(self, client_ip: str, reason: str = ""):
        self.client_ip = client_ip
        self.reason = reason
        super().__init__(f"Blocked IP: {client_ip} - {reason}")

class AttackDetected(SentinelShieldError):
    def __init__(self, rule_id: str, attack_type: str, confidence: float,
                 client_ip: str, location: str, payload: str):
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
