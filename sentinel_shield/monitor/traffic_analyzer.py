"""
Tracks live traffic stats in memory: how many requests, which status codes,
which paths, which attack types. Used by the admin API and the dashboard.
Stats reset when the process restarts; the log file is the durable record.
"""

import time
from collections import defaultdict, deque
from threading import Lock


class TrafficAnalyzer:
    def __init__(self, config):
        self.enabled = config.get("enabled", True)
        self.window_seconds = config.get("window_seconds", 300)
        self._lock = Lock()
        self._requests = defaultdict(lambda: deque(maxlen=100000))
        self._status_codes = defaultdict(int)
        self._attacks = defaultdict(int)

    def record(self, method, path, status_code):
        """Remember one request and its result."""
        if not self.enabled:
            return
        with self._lock:
            now = time.monotonic()
            self._requests[method].append((now, path, status_code))
            self._status_codes[str(status_code)] += 1

    def record_attack(self, attack_type):
        """Count one detected attack of a given type."""
        if not self.enabled:
            return
        with self._lock:
            self._attacks[attack_type] += 1

    def get_stats(self):
        """Summarise the last window_seconds of traffic."""
        if not self.enabled:
            return {"enabled": False}
        with self._lock:
            now = time.monotonic()
            cutoff = now - self.window_seconds
            total = 0
            requests_per_method = {}
            path_counts = defaultdict(int)

            for method, entries in list(self._requests.items()):
                count = 0
                for timestamp, path, _ in entries:
                    if timestamp >= cutoff:
                        count += 1
                        total += 1
                        path_counts[path] += 1
                requests_per_method[method] = count

            top_paths = [
                {"path": path, "count": count}
                for path, count in sorted(path_counts.items(), key=lambda item: -item[1])[:10]
            ]

            return {
                "enabled": True,
                "window_seconds": self.window_seconds,
                "total_requests": total,
                "requests_per_method": requests_per_method,
                "requests_per_second": round(total / self.window_seconds, 2),
                "status_code_distribution": dict(self._status_codes),
                "attack_counts": dict(self._attacks),
                "top_paths": top_paths,
            }

    def reset(self):
        """Clear all collected stats."""
        with self._lock:
            self._requests.clear()
            self._status_codes.clear()
            self._attacks.clear()
