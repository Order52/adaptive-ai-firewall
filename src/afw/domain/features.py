"""Behavioral feature contracts.

Features describe *behavior of one source against one application* within a
sliding window. They intentionally exclude WAF signature output, source
address, zone, scenario labels and timing of test schedules so the ML signal
stays independent of CRS and free of label leakage. WAF/IDS evidence enters
later, in correlation.
"""

from __future__ import annotations

from datetime import datetime
from ipaddress import IPv4Address

from pydantic import Field

from afw.domain.common import DomainModel


class FeatureSpec(DomainModel):
    name: str
    description: str
    unit: str
    log_scale: bool = False


FEATURES: tuple[FeatureSpec, ...] = (
    FeatureSpec(name="req_rate", description="requests per second", unit="req/s", log_scale=True),
    FeatureSpec(name="route_count", description="distinct route templates", unit="routes"),
    FeatureSpec(name="route_entropy", description="Shannon entropy of route usage", unit="bits"),
    FeatureSpec(
        name="unknown_route_frac",
        description="share of requests to routes absent from the profile",
        unit="ratio",
    ),
    FeatureSpec(
        name="novel_method_frac",
        description="share of requests using a method not profiled for the route",
        unit="ratio",
    ),
    FeatureSpec(name="write_frac", description="share of state-changing methods", unit="ratio"),
    FeatureSpec(name="client_err_frac", description="share of 4xx responses", unit="ratio"),
    FeatureSpec(name="server_err_frac", description="share of 5xx responses", unit="ratio"),
    FeatureSpec(
        name="login_rate", description="login attempts per minute", unit="req/min", log_scale=True
    ),
    FeatureSpec(name="auth_fail_frac", description="failed share of login attempts", unit="ratio"),
    FeatureSpec(
        name="distinct_usernames",
        description="distinct usernames attempted",
        unit="users",
        log_scale=True,
    ),
    FeatureSpec(
        name="req_bytes_p95", description="95th pct request size", unit="bytes", log_scale=True
    ),
    FeatureSpec(
        name="interarrival_cv",
        description="coefficient of variation of inter-request gaps (regularity)",
        unit="ratio",
    ),
)

FEATURE_NAMES: tuple[str, ...] = tuple(f.name for f in FEATURES)
FEATURE_BY_NAME: dict[str, FeatureSpec] = {f.name: f for f in FEATURES}


class WindowSpec(DomainModel):
    length_s: int = Field(default=30, ge=5, le=600)
    hop_s: int = Field(default=5, ge=1, le=60)
    min_requests: int = Field(default=3, ge=1)


class FeatureVector(DomainModel):
    """Features for one (application, source) window.

    ``evidence`` carries non-ML context for correlation (WAF hits etc.) and is
    never fed to the anomaly models.
    """

    app_id: str
    source_ip: IPv4Address
    window_start: datetime
    window_end: datetime
    n_requests: int
    values: dict[str, float]
    app_versions: tuple[str, ...] = ()
    evidence: dict[str, float] = Field(default_factory=dict)
    request_ids: tuple[str, ...] = ()
    # SV-1: the window's ``values`` recomputed WITHOUT the requests behind a piece of
    # non-behaviour evidence, keyed like ``independence_key`` ("auth", "waf",
    # "auth+waf"); a residual is None when nothing would remain. Keys exist only for
    # categories the window has requests for. The field is None for vectors recorded
    # before residuals existed. A behaviour anomaly is independent of that evidence
    # only if the residual window is anomalous on its own.
    residuals: dict[str, dict[str, float] | None] | None = None

    def as_row(self) -> list[float]:
        return [self.values[name] for name in FEATURE_NAMES]
