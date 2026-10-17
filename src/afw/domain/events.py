"""Normalized security telemetry.

Raw sensor records (WAF access/audit logs, application events, Suricata EVE
alerts) are parsed by telemetry adapters into these vendor-neutral events.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address

from pydantic import Field

from afw.domain.common import DomainModel


class Sensor(StrEnum):
    WAF = "waf"
    APP = "app"
    IDS = "ids"
    FIREWALL = "firewall"


class AuthOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"


class HttpObservation(DomainModel):
    """One HTTP request as seen by the WAF, optionally enriched by the application.

    ``client_ip`` comes from the WAF's own transport peer (never a client header).
    ``auth_outcome`` is ``None`` when the application reported no outcome or its
    event has not (yet) been joined; ``app_joined`` distinguishes the two.
    """

    event_id: str
    request_id: str
    app_id: str
    observed_at: datetime
    client_ip: IPv4Address
    method: str
    path: str
    route: str
    status: int
    bytes_in: int = 0
    bytes_out: int = 0
    duration_ms: float = 0.0
    user_agent_hash: str | None = None
    waf_rule_ids: tuple[int, ...] = ()
    waf_anomaly_score: int = 0
    waf_blocked: bool = False
    app_joined: bool = False
    auth_outcome: AuthOutcome | None = None
    username_hash: str | None = None
    app_version: str | None = None
    reached_backend: bool = False


class IdsAlert(DomainModel):
    event_id: str
    observed_at: datetime
    sensor_id: str
    src_ip: IPv4Address
    dst_ip: IPv4Address
    dst_port: int | None = None
    proto: str
    signature_id: int
    signature: str
    severity: int = Field(ge=1, le=4)
    flow_id: int | None = None


class AppEvent(DomainModel):
    """Application-side record keyed by the WAF-issued request id."""

    request_id: str
    app_id: str
    observed_at: datetime
    route: str
    method: str
    status: int
    app_version: str
    auth_outcome: AuthOutcome | None = None
    username_hash: str | None = None
