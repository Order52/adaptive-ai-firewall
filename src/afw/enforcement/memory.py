"""In-memory enforcement backend and probe for tests and offline simulation.

Clearly a test double: it never touches a network device.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address

from afw.domain.policy import PolicyKind
from afw.ports.enforcement import ApplyReport, DesiredState, ObservedState


@dataclass
class MemoryBackend:
    name: str = "memory-firewall"
    handles: frozenset[PolicyKind] = frozenset(
        {
            PolicyKind.SOURCE_BLOCK,
            PolicyKind.GEO_BLOCK,
            PolicyKind.WAF_DENY,
            PolicyKind.RATE_LIMIT,
            PolicyKind.HTTP_CONTRACT,
            PolicyKind.LOGIN_CONTROL,
        }
    )
    state: DesiredState = field(default_factory=DesiredState)
    fail_next: int = 0
    timeout_next: int = 0
    unreachable: bool = False
    drop_on_apply: bool = False  # simulates an API that "succeeds" but does nothing
    apply_calls: int = 0
    killed: list[IPv4Address] = field(default_factory=list)
    heartbeats: int = 0

    def observe(self) -> ObservedState:
        if self.unreachable:
            return ObservedState(backend=self.name, reachable=False, error="unreachable")
        return ObservedState(
            backend=self.name,
            reachable=True,
            blocked_sources=self.state.blocked_sources,
            waf_denied_sources=self.state.waf_denied_sources,
            rate_limited=dict(self.state.rate_limited),
            login_controls=dict(self.state.login_controls),
            contracts=self.state.contracts,
            geo_inbound=self.state.geo_inbound,
            geo_outbound=self.state.geo_outbound,
        )

    def reconcile(self, desired: DesiredState) -> ApplyReport:
        self.apply_calls += 1
        if self.unreachable:
            return ApplyReport(backend=self.name, ok=False, error="unreachable", ambiguous=True)
        if self.timeout_next:
            self.timeout_next -= 1
            self.state = desired  # the change landed, but we never heard back
            return ApplyReport(backend=self.name, ok=False, error="timeout", ambiguous=True)
        if self.fail_next:
            self.fail_next -= 1
            return ApplyReport(backend=self.name, ok=False, error="injected failure")
        before = self.state.blocked_sources
        if not self.drop_on_apply:
            self.state = desired
        return ApplyReport(
            backend=self.name,
            ok=True,
            added=tuple(str(i) for i in desired.blocked_sources - before),
            removed=tuple(str(i) for i in before - desired.blocked_sources),
        )

    def kill_states(self, source: IPv4Address) -> int:
        self.killed.append(source)
        return 1

    def heartbeat(self) -> None:
        self.heartbeats += 1


@dataclass
class MemoryProbe:
    backend: MemoryBackend
    service_up: bool = True
    internet_up: bool = True
    egress: dict[str, str] = field(default_factory=dict)

    def legitimate_ok(self) -> bool | None:
        return self.service_up

    def source_blocked(self, source: IPv4Address) -> bool | None:
        if not self.service_up:
            return True
        return source in self.backend.state.blocked_sources

    def egress_connects(self, source: IPv4Address, target: str) -> bool | None:
        """Unknown targets are unverifiable (None); others connect unless their
        country (``egress``: target name -> country) is blocked outbound."""
        cc = self.egress.get(target)
        if cc is None:
            return None
        return self.internet_up and cc not in self.backend.state.geo_outbound
