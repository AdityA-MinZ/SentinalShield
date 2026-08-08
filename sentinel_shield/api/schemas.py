"""
Request/response models for the admin API. Pydantic uses these to validate
and document the API (they show up in the auto-generated /docs page).
"""

from pydantic import BaseModel
from typing import List, Optional


class HealthResponse(BaseModel):
    status: str
    version: str
    uptime: float


class StatsResponse(BaseModel):
    enabled: bool
    window_seconds: Optional[int] = None
    total_requests: Optional[int] = None
    requests_per_method: Optional[dict] = None
    requests_per_second: Optional[float] = None
    status_code_distribution: Optional[dict] = None
    attack_counts: Optional[dict] = None
    top_paths: Optional[List[dict]] = None


class RuleInfo(BaseModel):
    id: str
    name: str
    attack_type: str
    severity: str
    locations: List[str]
    action: str
    pattern_count: int


class RuleListResponse(BaseModel):
    count: int
    rules: List[RuleInfo]


class ConfigResponse(BaseModel):
    server: dict
    detection: dict
    rate_limiter: dict
    logging: dict


class IPActionRequest(BaseModel):
    ip: str
    action: str


class IPActionResponse(BaseModel):
    status: str
    ip: str
    action: str
    message: str
