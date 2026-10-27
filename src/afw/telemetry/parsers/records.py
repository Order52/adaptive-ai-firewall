"""Parsed (still sensor-specific) telemetry records."""

from __future__ import annotations

from datetime import datetime
from ipaddress import IPv4Address

from afw.domain.common import DomainModel
from afw.domain.events import AuthOutcome


class WafAccess(DomainModel):
    request_id: str
    observed_at: datetime
    client_ip: IPv4Address
    method: str
    path: str
    status: int
    bytes_in: int
    bytes_out: int
    duration_ms: float
    upstream_status: int | None
    user_agent_hash: str | None
    sensor_ip: IPv4Address | None = None
    app_id: str | None = None
    authenticated: bool = False  # arrived over mTLS from the WAF sensor identity


class WafAudit(DomainModel):
    request_id: str
    observed_at: datetime
    client_ip: IPv4Address
    rule_ids: tuple[int, ...]
    anomaly_score: int
    blocked: bool
    authenticated: bool = False  # arrived over mTLS from the WAF sensor identity


class AppRecord(DomainModel):
    request_id: str
    app_id: str
    observed_at: datetime
    route: str
    method: str
    status: int
    app_version: str
    auth_outcome: AuthOutcome | None
    username_hash: str | None
    authenticated: bool = False  # arrived over mTLS from the APP sensor identity


class SuricataAlert(DomainModel):
    observed_at: datetime
    sensor_id: str
    src_ip: IPv4Address
    dst_ip: IPv4Address
    dst_port: int | None
    proto: str
    signature_id: int
    signature: str
    severity: int
    flow_id: int | None
