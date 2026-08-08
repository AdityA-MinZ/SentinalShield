"""
The admin API (FastAPI). It exposes stats and live controls over HTTP:

    GET  /health         service status
    GET  /stats          traffic stats
    GET  /rules          loaded rules
    GET  /config         current config
    GET  /rate-limiter   rate limiter stats
    GET  /ip-reputation  blocked / allowed IPs
    POST /ip             block/unblock/allow an IP
    POST /reload-rules   re-read the rule files
    POST /reset-stats    clear traffic stats
"""

import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from ..core.config import Config
from ..detection.rules_engine import RulesEngine
from ..protection.rate_limiter import RateLimiter
from ..protection.ip_reputation import IPReputation
from ..monitor.traffic_analyzer import TrafficAnalyzer

from .schemas import (
    HealthResponse, StatsResponse, RuleInfo, RuleListResponse,
    ConfigResponse, IPActionRequest, IPActionResponse,
)

VERSION = "1.0.0"


def create_api(
    config: Config,
    rules_engine: RulesEngine,
    rate_limiter: RateLimiter,
    ip_reputation: IPReputation,
    traffic_analyzer: TrafficAnalyzer,
):
    app = FastAPI(
        title="SentinelShield Admin API",
        version=VERSION,
        description="Administration API for SentinelShield WAF/IDS",
    )
    start_time = time.monotonic()

    @app.get("/health", response_model=HealthResponse)
    async def health():
        return HealthResponse(
            status="ok",
            version=VERSION,
            uptime=time.monotonic() - start_time,
        )

    @app.get("/stats", response_model=StatsResponse)
    async def stats():
        return StatsResponse(**traffic_analyzer.get_stats())

    @app.get("/rules", response_model=RuleListResponse)
    async def list_rules():
        rules = []
        for r in rules_engine.rules:
            rules.append(RuleInfo(
                id=r["id"],
                name=r.get("name", ""),
                attack_type=r.get("attack_type", ""),
                severity=r.get("severity", "medium"),
                locations=r.get("locations", []),
                action=r.get("action", "block"),
                pattern_count=len(r.get("patterns", [])),
            ))
        return RuleListResponse(count=len(rules), rules=rules)

    @app.get("/config", response_model=ConfigResponse)
    async def get_config():
        return ConfigResponse(
            server=config.server,
            detection=config.detection,
            rate_limiter=config.rate_limiter,
            logging=config.logging,
        )

    @app.get("/rate-limiter", response_model=dict)
    async def rate_limiter_stats():
        return rate_limiter.get_stats()

    @app.get("/ip-reputation", response_model=dict)
    async def ip_reputation_stats():
        return ip_reputation.get_stats()

    @app.post("/ip", response_model=IPActionResponse)
    async def manage_ip(req: IPActionRequest):
        valid_actions = {"block", "unblock", "allow", "remove_allow"}
        if req.action not in valid_actions:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid action. Must be one of: {valid_actions}"
            )

        if req.action == "block":
            ip_reputation.block_ip(req.ip)
            msg = f"IP {req.ip} added to blocklist"
        elif req.action == "unblock":
            ip_reputation.unblock_ip(req.ip)
            msg = f"IP {req.ip} removed from blocklist"
        elif req.action == "allow":
            ip_reputation.allow_ip(req.ip)
            msg = f"IP {req.ip} added to allowlist"
        else:
            ip_reputation.remove_allow_ip(req.ip)
            msg = f"IP {req.ip} removed from allowlist"

        return IPActionResponse(
            status="ok", ip=req.ip,
            action=req.action, message=msg,
        )

    @app.post("/reload-rules")
    async def reload_rules():
        rules_engine.reload()
        return {"status": "ok", "message": "Rules reloaded"}

    @app.post("/reset-stats")
    async def reset_stats():
        traffic_analyzer.reset()
        return {"status": "ok", "message": "Stats reset"}

    return app
