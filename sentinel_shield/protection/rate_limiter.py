import time
from collections import defaultdict


class TokenBucket:
    def __init__(self, rate: float, burst: int):
        self.rate = rate
        self.burst = burst
        self.tokens = burst
        self.last = time.monotonic()

    def allow(self) -> bool:
        now = time.monotonic()
        self.tokens = min(self.burst, self.tokens + (now - self.last) * self.rate)
        self.last = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


class RateLimiter:
    def __init__(self, config: dict):
        self.enabled = config.get("enabled", True)
        self.per_min = config.get("requests_per_minute", 60)
        self.burst = config.get("burst_size", 10)
        self.buckets = defaultdict(lambda: TokenBucket(self.per_min / 60.0, self.burst))
        self._last_cleanup = time.monotonic()

    def allow(self, ip: str) -> bool:
        if not self.enabled:
            return True
        self._cleanup()
        return self.buckets[ip].allow()

    def _cleanup(self):
        now = time.monotonic()
        if now - self._last_cleanup < 300.0:
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
            "requests_per_minute": self.per_min,
            "burst_size": self.burst,
            "active_clients": len(self.buckets),
        }
