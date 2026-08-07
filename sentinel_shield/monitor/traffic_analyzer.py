import time
from collections import defaultdict, deque
from threading import Lock
from typing import Dict, List, Optional


class TrafficAnalyzer:
    def __init__(self, config: dict):
        self.enabled = config.get("enabled", True)
        self.window_seconds = config.get("window_seconds", 300)
        self._lock = Lock()
        self._requests: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=100000)
        )
        self._status_codes: Dict[str, int] = defaultdict(int)
        self._attack_counts: Dict[str, int] = defaultdict(int)
        self._last_status: int = 200

    def record(self, method: str, path: str, status_code: int):
        if not self.enabled:
            return
        with self._lock:
            now = time.monotonic()
            self._requests[method].append((now, path, status_code))
            self._status_codes[str(status_code)] += 1
            self._last_status = status_code

    def record_attack(self, attack_type: str):
        if not self.enabled:
            return
        with self._lock:
            self._attack_counts[attack_type] += 1

    def get_status_code(self) -> int:
        return self._last_status

    def get_stats(self) -> dict:
        if not self.enabled:
            return {"enabled": False}
        with self._lock:
            now = time.monotonic()
            cutoff = now - self.window_seconds
            total = 0
            method_counts = {}
            active_paths = defaultdict(int)

            for method, entries in list(self._requests.items()):
                count = 0
                for ts, path, _ in entries:
                    if ts >= cutoff:
                        count += 1
                        total += 1
                        active_paths[path] += 1
                method_counts[method] = count

            top_paths = sorted(
                active_paths.items(), key=lambda x: -x[1]
            )[:10]

            return {
                "enabled": True,
                "window_seconds": self.window_seconds,
                "total_requests": total,
                "requests_per_method": method_counts,
                "requests_per_second": round(total / self.window_seconds, 2),
                "status_code_distribution": dict(self._status_codes),
                "attack_counts": dict(self._attack_counts),
                "top_paths": [
                    {"path": p, "count": c} for p, c in top_paths
                ],
            }

    def reset(self):
        with self._lock:
            self._requests.clear()
            self._status_codes.clear()
            self._attack_counts.clear()
