from .core.engine import SentinelShield
from .core.config import Config
from .core.exceptions import (
    SentinelShieldError,
    ConfigError,
    DetectionError,
    AttackDetected,
    RateLimitExceeded,
    BlockedIP,
)

__version__ = "1.0.0"
__all__ = [
    "SentinelShield",
    "Config",
    "SentinelShieldError",
    "ConfigError",
    "DetectionError",
    "AttackDetected",
    "RateLimitExceeded",
    "BlockedIP",
]
