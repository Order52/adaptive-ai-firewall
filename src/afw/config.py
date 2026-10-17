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
    listen_port: int = 5514
    allowed_senders: tuple[IPv4Address, ...] = ()
    queue_size: int = 2000
    max_line_bytes: int = 65536
    join_wait_s: float = 2.0
    waf_sensor_ips: tuple[IPv4Address, ...] = ()


class ProbeAgentConfig(_Cfg):
    url: str
    owns: IPv4Network
    token_file: Path


class ProbeConfig(_Cfg):
    agents: tuple[ProbeAgentConfig, ...]
    legitimate_source: IPv4Address
    timeout_s: float = 6.0


class LabConfig(_Cfg):
    name: str
    zones: tuple[ZoneConfig, ...]
    services: tuple[ServiceConfig, ...]
    applications: tuple[ApplicationConfig, ...]
    safety: SafetyConfig
    risk: RiskConfig = RiskConfig()
    window: WindowSpec = WindowSpec()
    telemetry: TelemetryConfig = TelemetryConfig()
    opnsense: OpnsenseConfig | None = None
    waf_helper: WafHelperConfig | None = None
    probes: ProbeConfig | None = None
    initial_mode: OperatingMode = OperatingMode.MONITOR
    # SIMULATED GeoIP for the optional country-policy extension: fictitious
    # country -> lab client addresses. Never real geography; policies using it
    # must carry simulated=True and are labelled as such everywhere.
    geo_simulation: dict[str, tuple[IPv4Address, ...]] = {}

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
