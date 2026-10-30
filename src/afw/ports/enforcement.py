"""Enforcement port.

Backends receive the complete *desired state* for the scope they own and make
the device match it (level-triggered reconciliation). This makes duplicate
decisions, overlapping policies and controller restarts naturally idempotent.
"""

from __future__ import annotations

from ipaddress import IPv4Address
from typing import Protocol

from pydantic import Field

from afw.domain.common import DomainModel
from afw.domain.policy import ContractTarget, PolicyKind, RateProfile


class DesiredState(DomainModel):
    blocked_sources: frozenset[IPv4Address] = frozenset()
    waf_denied_sources: frozenset[IPv4Address] = frozenset()
    rate_limited: dict[IPv4Address, RateProfile] = Field(default_factory=dict)
    # A3: login routes only; LOGIN_THROTTLE or LOGIN_DENY per source
    login_controls: dict[IPv4Address, RateProfile] = Field(default_factory=dict)
    contracts: tuple[ContractTarget, ...] = ()
    # real-country policies (ADR-036): ISO codes per direction
    geo_inbound: frozenset[str] = frozenset()
    geo_outbound: frozenset[str] = frozenset()
    # countries of expiring/rolled-back real policies whose removal must be read back
    geo_watch: frozenset[str] = frozenset()


class ObservedState(DomainModel):
    backend: str
    reachable: bool
    blocked_sources: frozenset[IPv4Address] | None = None
    waf_denied_sources: frozenset[IPv4Address] | None = None
    rate_limited: dict[IPv4Address, RateProfile] | None = None
    login_controls: dict[IPv4Address, RateProfile] | None = None
    contracts: tuple[ContractTarget, ...] | None = None
    revision: str | None = None
    # countries whose every network is in the live pf table (read back)
    geo_inbound: frozenset[str] | None = None
    geo_outbound: frozenset[str] | None = None
    error: str | None = None


class ApplyReport(DomainModel):
    backend: str
    ok: bool
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    states_killed: int = 0
    error: str | None = None
    ambiguous: bool = Field(
        default=False, description="True when the outcome is unknown, e.g. a timeout"
    )


class EnforcementBackend(Protocol):
    name: str
    handles: frozenset[PolicyKind]

    def observe(self) -> ObservedState: ...
    def reconcile(self, desired: DesiredState) -> ApplyReport: ...
    def kill_states(self, source: IPv4Address) -> int: ...


class TrafficProbe(Protocol):
    """Fixed-target verification probes (positive and negative)."""

    def legitimate_ok(self) -> bool | None: ...
    def source_blocked(self, source: IPv4Address) -> bool | None: ...
    def egress_connects(self, source: IPv4Address, target: str) -> bool | None:
        """One TCP connect from ``source`` to a fixed, agent-allowlisted egress target."""
        ...
