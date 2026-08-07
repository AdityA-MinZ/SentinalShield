import time
from collections import defaultdict
from typing import Dict, List


class TokenBucket:
    def __init__(self, rate: float, burst: int):
        self.rate = rate
        self.burst = burst
        self.tokens = burst
        self.last_refill = time.monotonic()

    def allow(self) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(
            self.burst,
            self.tokens + elapsed * self.rate
        )
        self.last_refill = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


class RateLimiter:
    def __init__(self, config: dict):
        self.enabled = config.get("enabled", True)
        self.requests_per_minute = config.get("requests_per_minute", 60)
        self.burst_size = config.get("burst_size", 10)
        self.buckets: Dict[str, TokenBucket] = defaultdict(
            lambda: TokenBucket(
                rate=self.requests_per_minute / 60.0,
                burst=self.burst_size,
            )
        )
        self.cleanup_interval = 300.0
        self._last_cleanup = time.monotonic()

    def allow(self, client_ip: str) -> bool:
        if not self.enabled:
            return True
        self._cleanup()
        return self.buckets[client_ip].allow()

    def _cleanup(self):
        now = time.monotonic()
        if now - self._last_cleanup < self.cleanup_interval:
            return
        self._last_cleanup = now
        stale = []
        for ip, bucket in self.buckets.items():
            if bucket.tokens >= bucket.burst:
                stale.append(ip)
        for ip in stale:
            del self.buckets[ip]

    def get_stats(self) -> dict:
        return {
            "enabled": self.enabled,
            "requests_per_minute": self.requests_per_minute,
            "burst_size": self.burst_size,
            "active_clients": len(self.buckets),
        }
