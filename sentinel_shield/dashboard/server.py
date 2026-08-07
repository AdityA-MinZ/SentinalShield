import json
import os
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Optional

from flask import Flask, jsonify, render_template, request as flask_request

from ..core.config import Config
from ..detection.rules_engine import RulesEngine
from ..protection.rate_limiter import RateLimiter
from ..protection.ip_reputation import IPReputation
from ..monitor.traffic_analyzer import TrafficAnalyzer

app = Flask(__name__)

config: Optional[Config] = None
rules_engine: Optional[RulesEngine] = None
rate_limiter: Optional[RateLimiter] = None
ip_reputation: Optional[IPReputation] = None
traffic_analyzer: Optional[TrafficAnalyzer] = None


def init(cfg: Config):
    global config, rules_engine, rate_limiter, ip_reputation, traffic_analyzer
    config = cfg
    rules_engine = RulesEngine(cfg.rules_dir)
    rate_limiter = RateLimiter(cfg.rate_limiter)
    ip_reputation = IPReputation(cfg.ip_reputation)
    traffic_analyzer = TrafficAnalyzer(cfg.traffic_analyzer)


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/summary")
def api_summary():
    stats = traffic_analyzer.get_stats() if traffic_analyzer else {}
    rl_stats = rate_limiter.get_stats() if rate_limiter else {}
    ip_stats = ip_reputation.get_stats() if ip_reputation else {}
    rule_count = len(rules_engine.rules) if rules_engine else 0
    detection_mode = config.detection.get("mode", "log") if config else "log"

    log_stats = _log_summary()
    live_requests = stats.get("total_requests", 0)

    return jsonify({
        "total_requests": log_stats["total_requests"] or live_requests,
        "total_attacks": log_stats["total_attacks"],
        "attack_counts": log_stats["attack_counts"],
        "requests_per_second": stats.get("requests_per_second", 0),
        "requests_per_method": log_stats["requests_per_method"]
        or stats.get("requests_per_method", {}),
        "status_code_distribution": log_stats["status_code_distribution"]
        or stats.get("status_code_distribution", {}),
        "top_paths": log_stats["top_paths"] or stats.get("top_paths", []),
        "rate_limiter": rl_stats,
        "ip_reputation": ip_stats,
        "rule_count": rule_count,
        "detection_mode": detection_mode,
    })


@app.route("/api/logs")
def api_logs():
    limit = flask_request.args.get("limit", 50, type=int)
    events = _load_log_entries()[-limit:]
    events.reverse()
    return jsonify({"events": events})


@app.route("/api/rules")
def api_rules():
    if not rules_engine:
        return jsonify({"rules": []})
    rules = []
    for r in rules_engine.rules:
        rules.append({
            "id": r["id"],
            "name": r.get("name", ""),
            "attack_type": r.get("attack_type", ""),
            "severity": r.get("severity", "medium"),
            "locations": r.get("locations", []),
            "action": r.get("action", "block"),
            "pattern_count": len(r.get("patterns", [])),
        })
    return jsonify({"count": len(rules), "rules": rules})


@app.route("/api/attack-timeline")
def api_attack_timeline():
    timeline = Counter()
    for entry in _load_log_entries():
        event = entry.get("event", "")
        if event in ("block", "detection"):
            ts = entry.get("timestamp", "")
            minute = ts[:16] if len(ts) >= 16 else ts
            timeline[minute] += 1

    sorted_timeline = sorted(timeline.items())
    return jsonify({
        "timeline": [
            {"time": t, "count": c} for t, c in sorted_timeline[-30:]
        ]
    })


def _load_log_entries() -> list:
    log_file = _get_log_path()
    if not log_file or not log_file.exists():
        return []
    entries = []
    try:
        with open(log_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except (OSError, IOError):
        pass
    return entries


def _log_summary() -> dict:
    total_requests = 0
    attack_counts = Counter()
    status_codes = Counter()
    methods = Counter()
    paths = Counter()

    for e in _load_log_entries():
        event = e.get("event", "")
        if event == "access":
            total_requests += 1
            methods[e.get("method", "")] += 1
            status_codes[str(e.get("status", 0))] += 1
            paths[e.get("path", "")] += 1
        elif event in ("block", "detection"):
            atype = e.get("attack_type", "") or e.get("reason_type", "")
            if atype:
                attack_counts[atype] += 1
            paths[e.get("path", "")] += 1

    return {
        "total_requests": total_requests,
        "total_attacks": sum(attack_counts.values()),
        "attack_counts": dict(attack_counts.most_common()),
        "requests_per_method": dict(methods),
        "status_code_distribution": dict(status_codes.most_common()),
        "top_paths": paths.most_common(10),
    }


def _get_log_path() -> Optional[Path]:
    if config and config.logging:
        log_path = config.logging.get("file")
        if log_path:
            return Path(log_path)
    default = Path("sentinel-shield.log")
    if default.exists():
        return default
    return None


def create_app(cfg: Config) -> Flask:
    init(cfg)
    return app
