"""Validated configuration.

Topology, services and safety bounds come from a YAML file (``AFW_CONFIG``);
secrets and runtime paths from environment variables / secret files. Nothing in
the codebase hardcodes lab addresses.
"""

from __future__ import annotations

from functools import lru_cache
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from afw.domain.features import WindowSpec
from afw.domain.policy import OperatingMode, PolicyKind


class _Cfg(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ServiceConfig(_Cfg):
    name: str
    app_id: str
    address: IPv4Address
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp"] = "tcp"


class RouteDeclaration(_Cfg):
    """Application-owner declaration of an endpoint (the API contract)."""

    route: str
    methods: tuple[str, ...]
    content_types: tuple[str, ...] = ()
    max_body_bytes: int = 0
    login: bool = False


class ApplicationConfig(_Cfg):
    app_id: str
    service: str
    routes: tuple[RouteDeclaration, ...]

    def login_routes(self) -> frozenset[str]:
        return frozenset(r.route for r in self.routes if r.login)


class ZoneConfig(_Cfg):
    name: str
    network: IPv4Network
    clients: bool = False


class ProtectedConfig(_Cfg):
    network: IPv4Network
    reason: str


class SafetyConfig(_Cfg):
    protected: tuple[ProtectedConfig, ...]
    min_duration_s: int = 30
    max_auto_duration_s: int = 300
    max_duration_s: int = 3600
    max_active_policies: int = 100
    max_auto_actions_per_minute: int = 10
    auto_kinds: frozenset[PolicyKind] = frozenset(
        {PolicyKind.WATCH, PolicyKind.RATE_LIMIT, PolicyKind.SOURCE_BLOCK, PolicyKind.WAF_DENY}
    )
    require_corroboration_for_block: int = Field(
        default=2, description="independent evidence categories required for any block"
    )
    behavior_only_rate_limit: bool = Field(
        default=True,
        description="rate limit a source whose only evidence is behavioural when the "
        "statistical and an ML detector agree (pre-2026-10-28 behaviour). Both read the "
        "same features, so their agreement is not independent corroboration; False makes "
        "behaviour-only evidence observe-only (P6 amendment A2). Changing it on a live "
        "deployment needs human authorization",
    )
    shared_address_min_accounts: int = Field(
        default=3,
        ge=2,
        description="distinct accounts with a recent successful login that make an "
        "address shared (NAT/proxy); a block on it is downgraded to a rate limit that "
        "needs human approval (ADR-043)",
    )
    shared_address_window_s: int = Field(default=3600, ge=60)


class RiskConfig(_Cfg):
    watch: float = 25
    rate_limit: float = 45
    block: float = 65
    escalate: float = 85
    history_half_life_s: float = 900
    base_block_s: int = 120
    escalation_factor: float = 2.0


class OpnsenseConfig(_Cfg):
    base_url: str
    alias: str = "AFW_BLOCK_WEB"
    key_file: Path
    secret_file: Path
    ca_file: Path | None = None
    verify_tls: bool = True
    timeout_s: float = 5.0
    kill_states: bool = True


class WafHelperConfig(_Cfg):
    base_url: str
    token_file: Path
    ca_file: Path | None = None
    verify_tls: bool = True
    timeout_s: float = 8.0


class TelemetryConfig(_Cfg):
    listen_host: str = "0.0.0.0"  # noqa: S104 - bound to the MGMT NIC on CTRL01
    listen_port: int | None = 5514  # plaintext listener; None disables it
    allowed_senders: tuple[IPv4Address, ...] = ()
    queue_size: int = 2000
    max_line_bytes: int = 65536
    join_wait_s: float = 2.0
    waf_sensor_ips: tuple[IPv4Address, ...] = ()
    # Mutually authenticated TLS channel (ADR-029). Each client certificate
    # common name maps to the one sensor role allowed to send on it ("waf", "app"
    # or "ids"). Lines of another kind on that channel are dropped.
    tls_port: int | None = None
    tls_allowed_senders: tuple[IPv4Address, ...] = ()
    tls_cert: Path | None = None
    tls_key: Path | None = None
    tls_ca: Path | None = None
    tls_identities: dict[str, str] = {}
    # RELP over the same mutual TLS (same certificates, identities and senders): each
    # line is acknowledged only once queued, so a dead session loses nothing (the
    # sender resends unacknowledged frames). None disables it.
    relp_port: int | None = None


class OnlineLearningConfig(_Cfg):
    """Shadow online learner (ADR-028). Defaults are deliberately conservative."""

    enabled: bool = True
    admission_delay_s: int = Field(default=600, ge=0)  # quarantine before learning
    min_source_tenure_s: int = Field(default=1800, ge=0)
    max_windows_per_source_per_hour: int = Field(default=20, ge=1)
    max_source_share: float = Field(default=0.25, gt=0, le=1)  # of the last share_window
    share_window: int = Field(default=200, ge=10)
    min_distinct_sources: int = Field(default=3, ge=1)  # released recently (population)
    population_window_s: int = Field(default=3600, ge=60)
    # A window the trusted detectors call anomalous is learnable only if the
    # same anomaly signature is shown by this many distinct clean sources.
    anomaly_min_sources: int = Field(default=3, ge=2)
    # ...and "same" means behaviourally close: L-infinity distance in the champion
    # HST's scaled space (a benign q01..q99 range spans ~1/3 of it). Sharing anomaly
    # driver *names* is not enough (M4 finding: benign drift vouched for poison).
    anomaly_max_distance: float = Field(default=0.35, gt=0, le=1)
    taint_ttl_s: int = Field(default=86_400, ge=60)
    quarantine_max: int = Field(default=5000, ge=10)
    queue_max: int = Field(default=2000, ge=10)
    checkpoint_every: int = Field(default=50, ge=1)
    checkpoint_interval_s: int = Field(default=300, ge=1)
    keep_checkpoints: int = Field(default=3, ge=1)
    retention_days: int = Field(default=7, ge=1)  # shadow scores, idle sources


class PromotionConfig(_Cfg):
    """Challenger evaluation, human-approved promotion and probation (ADR-030)."""

    target_fpr: float = Field(default=0.01, gt=0, lt=0.5)  # threshold calibration
    min_holdout_windows: int = Field(default=30, ge=10)  # per half, non-overlapping
    recall_tolerance: float = Field(default=0.05, ge=0, le=1)
    sensitive_tolerance: float = Field(default=0.05, ge=0, le=1)
    max_evaluation_age_s: int = Field(default=86_400, ge=60)
    probation_s: int = Field(default=86_400, ge=60)
    probation_min_windows: int = Field(default=100, ge=10)
    # roll back when the promoted model's live anomalous rate exceeds
    # max(rate_factor * baseline, baseline + rate_margin)
    probation_rate_factor: float = Field(default=2.0, ge=1)
    probation_rate_margin: float = Field(default=0.05, ge=0)
    probation_max_false_positives: int = Field(default=3, ge=1)


class ProbeAgentConfig(_Cfg):
    url: str
    owns: IPv4Network
    token_file: Path


class ProbeConfig(_Cfg):
    agents: tuple[ProbeAgentConfig, ...]
    legitimate_source: IPv4Address
    timeout_s: float = 6.0


class EgressTarget(_Cfg):
    address: IPv4Address
    port: int = Field(default=443, ge=1, le=65535)


class GeoEnforcementConfig(_Cfg):
    """Real-country enforcement (ADR-036). FW01 pulls one network list per direction
    from the controller into the pf tables of two pre-installed rules; the controller
    verifies by reading the tables back with its least-privilege key."""

    enabled: bool = False
    inbound_alias: str = "AFW_GEO_IN"
    outbound_alias: str = "AFW_GEO_OUT"
    max_networks: int = Field(default=40_000, ge=1, description="per direction, all countries")
    # Fixed outbound verification targets. The probe agents carry the same list and
    # accept only these names (no free-form destination). Their country comes from GeoIP.
    egress_targets: dict[str, EgressTarget] = {}
    egress_source: IPv4Address | None = None  # agent-owned address in a zone the rule covers


class LabConfig(_Cfg):
    name: str
    zones: tuple[ZoneConfig, ...]
    services: tuple[ServiceConfig, ...]
    applications: tuple[ApplicationConfig, ...]
    safety: SafetyConfig
    risk: RiskConfig = RiskConfig()
    window: WindowSpec = WindowSpec()
    telemetry: TelemetryConfig = TelemetryConfig()
    learning: OnlineLearningConfig = OnlineLearningConfig()
    promotion: PromotionConfig = PromotionConfig()
    opnsense: OpnsenseConfig | None = None
    waf_helper: WafHelperConfig | None = None
    probes: ProbeConfig | None = None
    initial_mode: OperatingMode = OperatingMode.MONITOR
    # SIMULATED GeoIP for the optional country-policy extension: fictitious
    # country -> lab client addresses. Never real geography; policies using it
    # must carry simulated=True and are labelled as such everywhere.
    geo_simulation: dict[str, tuple[IPv4Address, ...]] = {}
    geo_enforcement: GeoEnforcementConfig = GeoEnforcementConfig()

    @model_validator(mode="after")
    def _references(self) -> LabConfig:
        names = {s.name for s in self.services}
        for app in self.applications:
            if app.service not in names:
                raise ValueError(f"application {app.app_id} references unknown service")
        return self

    def service(self, name: str) -> ServiceConfig:
        return next(s for s in self.services if s.name == name)

    def application(self, app_id: str) -> ApplicationConfig:
        return next(a for a in self.applications if a.app_id == app_id)

    def client_networks(self) -> tuple[IPv4Network, ...]:
        return tuple(z.network for z in self.zones if z.clients)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AFW_", env_file=".env", extra="ignore")

    config: Path = Path("config/lab.yaml")
    data_dir: Path = Path("var")
    database_url: str = ""
    api_tokens_file: Path = Path("secrets/api_tokens.yaml")
    tls_cert: Path | None = None  # AFW_TLS_CERT: server leaf cert (PEM) — enables HTTPS
    tls_key: Path | None = None  # AFW_TLS_KEY: matching private key (PEM)
    log_level: str = "INFO"
    log_json: bool = True

    def tls_enabled(self) -> bool:
        return bool(
            self.tls_cert and self.tls_key and self.tls_cert.exists() and self.tls_key.exists()
        )

    def db_url(self) -> str:
        return self.database_url or f"sqlite:///{self.data_dir / 'afw.sqlite3'}"

    def model_dir(self) -> Path:
        return self.data_dir / "models"


def load_lab_config(path: Path) -> LabConfig:
    with path.open() as fh:
        return LabConfig.model_validate(yaml.safe_load(fh))


@lru_cache
def get_settings() -> Settings:
    return Settings()
