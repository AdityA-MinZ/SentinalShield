"""
Rate limiting using the token bucket algorithm.

Every client IP gets its own bucket. A bucket starts full (all burst tokens).
Each request takes one token out. Over time tokens are added back at a fixed
rate (requests_per_minute / 60 = tokens per second). When a bucket is empty
the request is rejected with HTTP 429.
"""

import time
from collections import defaultdict


class TokenBucket:
    """A single client's bucket of available request tokens."""

    def __init__(self, tokens_per_second, burst_size):
        self.tokens_per_second = tokens_per_second   # new tokens per second
        self.burst_size = burst_size                 # maximum tokens held
        self.tokens = burst_size                     # start full
        self.last_refill_time = time.monotonic()     # last time we added tokens

    def take_token(self):
        """Consume one token if available. Returns True if allowed."""
        now = time.monotonic()
        elapsed = now - self.last_refill_time
        # Add the tokens that accumulated since the last request, capped at burst.
        self.tokens = min(self.burst_size, self.tokens + elapsed * self.tokens_per_second)
        self.last_refill_time = now

        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


class RateLimiter:
    """Keeps one token bucket per client IP."""

    def __init__(self, config):
        self.enabled = config.get("enabled", True)
        self.requests_per_minute = config.get("requests_per_minute", 60)
        self.burst_size = config.get("burst_size", 10)
        self.tokens_per_second = self.requests_per_minute / 60.0
        self.buckets = defaultdict(
            lambda: TokenBucket(self.tokens_per_second, self.burst_size)
        )
        self.last_cleanup_time = time.monotonic()
        self.cleanup_interval = 300.0  # how often we clean up idle buckets

    def allow(self, client_ip):
        """Return True if this IP may make another request."""
        if not self.enabled:
            return True
        self._cleanup_idle_buckets()
        return self.buckets[client_ip].take_token()

    def _cleanup_idle_buckets(self):
        """Forget buckets that are full again so memory does not grow forever."""
        now = time.monotonic()
        if now - self.last_cleanup_time < self.cleanup_interval:
            return
        self.last_cleanup_time = now

        for client_ip, bucket in list(self.buckets.items()):
            if bucket.tokens >= bucket.burst_size:
                del self.buckets[client_ip]

    def get_stats(self):
        return {
            "enabled": self.enabled,
            "requests_per_minute": self.requests_per_minute,
            "burst_size": self.burst_size,
            "active_clients": len(self.buckets),
        }
