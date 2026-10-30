"""Security policies, operating modes and the enforcement lifecycle.

Policies are structured, typed intents. No component — model, operator, MCP
client — can express a raw firewall command or free-form WAF text.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from ipaddress import IPv4Address, IPv4Network
from typing import Annotated, Literal

from pydantic import Field

from afw.domain.common import DomainModel


class OperatingMode(StrEnum):
    MONITOR = "monitor"  # decide and record only
    ASSISTED = "assisted"  # every mutating policy needs approval
    AUTO = "auto"  # limited automatic: only auto-eligible kinds within bounds


class PolicyOrigin(StrEnum):
    AI = "ai"
    OPERATOR = "operator"
    MCP = "mcp"
    SYSTEM = "system"


class PolicyKind(StrEnum):
    WATCH = "watch"  # increase monitoring; no traffic effect
    RATE_LIMIT = "rate_limit"  # WAF per-source rate profile
    SOURCE_BLOCK = "source_block"  # OPNsense alias, scoped to one protected service
    WAF_DENY = "waf_deny"  # WAF-level deny of one source for one application
    HTTP_CONTRACT = "http_contract"  # validated WAF route contract revision
    GEO_BLOCK = "geo_block"  # optional extension: country-scoped network policy
    LOGIN_CONTROL = "login_control"  # WAF control on the login routes only (A3)


class PolicyState(StrEnum):
    PROPOSED = "proposed"
    VALIDATED = "validated"
    REJECTED = "rejected"
    PENDING_APPROVAL = "pending_approval"
    APPLYING = "applying"
    APPLIED_UNVERIFIED = "applied_unverified"
    ENFORCED = "enforced"
    FAILED = "failed"
    UNKNOWN = "unknown"
    EXPIRING = "expiring"
    EXPIRED = "expired"
    ROLLBACK_PENDING = "rollback_pending"
    ROLLED_BACK = "rolled_back"
    SUPERSEDED = "superseded"


S = PolicyState
TRANSITIONS: dict[PolicyState, frozenset[PolicyState]] = {
    S.PROPOSED: frozenset({S.VALIDATED, S.REJECTED}),
    # VALIDATED -> EXPIRED: monitor-mode decisions are recorded, never applied.
    S.VALIDATED: frozenset({S.PENDING_APPROVAL, S.APPLYING, S.REJECTED, S.SUPERSEDED, S.EXPIRED}),
    S.PENDING_APPROVAL: frozenset({S.APPLYING, S.REJECTED, S.EXPIRED, S.SUPERSEDED}),
    S.APPLYING: frozenset({S.APPLIED_UNVERIFIED, S.FAILED, S.UNKNOWN}),
    S.APPLIED_UNVERIFIED: frozenset(
        {S.ENFORCED, S.FAILED, S.UNKNOWN, S.EXPIRING, S.ROLLBACK_PENDING}
    ),
    S.ENFORCED: frozenset({S.EXPIRING, S.ROLLBACK_PENDING, S.UNKNOWN, S.SUPERSEDED}),
    S.UNKNOWN: frozenset(
        {S.ENFORCED, S.APPLIED_UNVERIFIED, S.FAILED, S.EXPIRING, S.ROLLBACK_PENDING}
    ),
    S.FAILED: frozenset({S.APPLYING, S.ROLLBACK_PENDING, S.EXPIRED}),
    S.EXPIRING: frozenset({S.EXPIRED, S.UNKNOWN}),
    S.ROLLBACK_PENDING: frozenset({S.ROLLED_BACK, S.UNKNOWN}),
    S.EXPIRED: frozenset(),
    S.ROLLED_BACK: frozenset(),
    S.REJECTED: frozenset(),
    S.SUPERSEDED: frozenset({S.EXPIRING, S.EXPIRED}),
}

ACTIVE_STATES = frozenset({S.APPLYING, S.APPLIED_UNVERIFIED, S.ENFORCED, S.UNKNOWN})
TERMINAL_STATES = frozenset({S.EXPIRED, S.ROLLED_BACK, S.REJECTED})


class InvalidTransition(ValueError):
    pass


def check_transition(current: PolicyState, target: PolicyState) -> None:
    if target not in TRANSITIONS[current]:
        raise InvalidTransition(f"{current} -> {target} is not a permitted policy transition")


# ---- typed action targets ---------------------------------------------------


class SourceTarget(DomainModel):
    type: Literal["source"] = "source"
    source_ip: IPv4Address


class CountryTarget(DomainModel):
    type: Literal["country"] = "country"
    country_code: str = Field(pattern=r"^[A-Z]{2}$")
    direction: Literal["inbound", "outbound", "both"]
    simulated: bool = Field(
        description="True when lab addresses are mapped synthetically (not real GeoIP)"
    )


class ContractTarget(DomainModel):
    type: Literal["contract"] = "contract"
    route: str = Field(pattern=r"^/[A-Za-z0-9_\-/{}]*$", max_length=128)
    allowed_methods: tuple[Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"], ...]
    allowed_content_types: tuple[
        Literal["application/json", "application/x-www-form-urlencoded", "text/plain"], ...
    ] = ()
    max_body_bytes: int = Field(ge=0, le=1_048_576)
    revision: int = Field(ge=1)


PolicyTarget = Annotated[SourceTarget | CountryTarget | ContractTarget, Field(discriminator="type")]


class RateProfile(StrEnum):
    STRICT = "strict"  # e.g. 1 r/s burst 5
    MODERATE = "moderate"  # e.g. 5 r/s burst 10
    # login routes only (LOGIN_CONTROL, A3): 3 per minute burst 4, or refused (403)
    LOGIN_THROTTLE = "login_throttle"
    LOGIN_DENY = "login_deny"


LOGIN_PROFILES = frozenset({RateProfile.LOGIN_THROTTLE, RateProfile.LOGIN_DENY})
SITE_PROFILES = frozenset({RateProfile.STRICT, RateProfile.MODERATE})


class PolicyIntent(DomainModel):
    """What someone wants to happen, before validation."""

    kind: PolicyKind
    app_id: str
    service: str
    target: PolicyTarget
    duration_s: int | None = Field(default=None, ge=1)
    rate_profile: RateProfile | None = None
    origin: PolicyOrigin
    requested_by: str
    reason_codes: tuple[str, ...] = ()
    risk_assessment_id: str | None = None
    evidence_refs: tuple[str, ...] = ()
    escalation_level: int = Field(default=0, ge=0, le=5)


class StateChange(DomainModel):
    at: datetime
    from_state: PolicyState | None
    to_state: PolicyState
    actor: str
    note: str = ""


class Policy(DomainModel):
    policy_id: str
    idempotency_key: str
    intent: PolicyIntent
    state: PolicyState
    mode_at_creation: OperatingMode
    created_at: datetime
    updated_at: datetime
    effective_at: datetime | None = None
    expires_at: datetime | None = None
    approved_by: str | None = None
    validation_notes: tuple[str, ...] = ()
    enforcement_backend: str | None = None
    verification: dict[str, str | bool | float] = Field(default_factory=dict)
    history: tuple[StateChange, ...] = ()

    @property
    def kind(self) -> PolicyKind:
        return self.intent.kind

    def is_expired(self, now: datetime) -> bool:
        return self.expires_at is not None and now >= self.expires_at

    def with_state(self, target: PolicyState, actor: str, now: datetime, note: str = "") -> Policy:
        check_transition(self.state, target)
        change = StateChange(at=now, from_state=self.state, to_state=target, actor=actor, note=note)
        return self.model_copy(
            update={"state": target, "updated_at": now, "history": (*self.history, change)}
        )

    def activate(self, now: datetime) -> Policy:
        expires = (
            now + timedelta(seconds=self.intent.duration_s) if self.intent.duration_s else None
        )
        return self.model_copy(update={"effective_at": now, "expires_at": expires})


class ProtectedRange(DomainModel):
    network: IPv4Network
    reason: str
