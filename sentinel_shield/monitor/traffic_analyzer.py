import time
from collections import defaultdict, deque
from threading import Lock


class TrafficAnalyzer:
    def __init__(self, config: dict):
        self.enabled = config.get("enabled", True)
        self.window_seconds = config.get("window_seconds", 300)
        self._lock = Lock()
        self._reqs = defaultdict(lambda: deque(maxlen=100000))
        self._codes = defaultdict(int)
        self._attacks = defaultdict(int)
        self._last = 200

    def record(self, method: str, path: str, status_code: int):
        if not self.enabled:
            return
        with self._lock:
            now = time.monotonic()
            self._reqs[method].append((now, path, status_code))
            self._codes[str(status_code)] += 1
            self._last = status_code

    def record_attack(self, attack_type: str):
        if not self.enabled:
            return
        with self._lock:
            self._attacks[attack_type] += 1

    def get_status_code(self) -> int:
        return self._last

    def get_stats(self) -> dict:
        if not self.enabled:
            return {"enabled": False}
        with self._lock:
            now = time.monotonic()
            cutoff = now - self.window_seconds
            total = 0
            per_method = {}
            paths = defaultdict(int)

            for method, entries in list(self._reqs.items()):
                count = 0
                for ts, path, _ in entries:
                    if ts >= cutoff:
                        count += 1
                        total += 1
                        paths[path] += 1
                per_method[method] = count

            ranked = sorted(paths.items(), key=lambda x: -x[1])[:10]
            top = []
            for p, c in ranked:
                top.append({"path": p, "count": c})

            return {
                "enabled": True,
                "window_seconds": self.window_seconds,
                "total_requests": total,
                "requests_per_method": per_method,
                "requests_per_second": round(total / self.window_seconds, 2),
                "status_code_distribution": dict(self._codes),
                "attack_counts": dict(self._attacks),
                "top_paths": top,
            }

    def reset(self):
        with self._lock:
            self._reqs.clear()
            self._codes.clear()
            self._attacks.clear()
