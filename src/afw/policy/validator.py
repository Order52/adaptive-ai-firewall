"""The single safety gate for every policy, whatever its origin (AI, operator, MCP)."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ipaddress import IPv4Address

from afw.config import LabConfig
from afw.domain.policy import (
    ContractTarget,
    CountryTarget,
    OperatingMode,
    PolicyIntent,
    PolicyKind,
    PolicyOrigin,
    SourceTarget,
)

GLOBAL_BODY_CEILING = 1_048_576


@dataclass(frozen=True)
class Verdict:
    ok: bool
    errors: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    auto_eligible: bool = False


@dataclass
class PolicyValidator:
    cfg: LabConfig
    _auto_log: deque[datetime] = field(default_factory=lambda: deque(maxlen=1000))

    def validate(
        self,
        intent: PolicyIntent,
        mode: OperatingMode,
        active_count: int,
        now: datetime,
        degraded_telemetry: bool = False,
    ) -> Verdict:
        errors: list[str] = []
        notes: list[str] = []
        s = self.cfg.safety

        try:
            app = self.cfg.application(intent.app_id)
        except StopIteration:
            return Verdict(ok=False, errors=(f"unknown application {intent.app_id!r}",))
        if intent.service != app.service:
            errors.append(f"service {intent.service!r} does not belong to {intent.app_id!r}")

        target = intent.target
        match intent.kind:
            case (
                PolicyKind.WATCH
                | PolicyKind.RATE_LIMIT
                | PolicyKind.SOURCE_BLOCK
                | (PolicyKind.WAF_DENY)
            ):
                if not isinstance(target, SourceTarget):
                    errors.append(f"{intent.kind} requires a single source target")
                else:
                    errors += self._check_source(target)
                if intent.kind is PolicyKind.RATE_LIMIT and intent.rate_profile is None:
                    errors.append("rate_limit requires an approved rate_profile")
                if intent.kind is not PolicyKind.WATCH:
                    errors += self._check_duration(intent.duration_s)
            case PolicyKind.HTTP_CONTRACT:
                if not isinstance(target, ContractTarget):
                    errors.append("http_contract requires a contract target")
                else:
                    errors += self._check_contract(intent.app_id, target)
                if intent.duration_s is not None:
                    errors.append("contracts are revisioned, not time-limited")
            case PolicyKind.GEO_BLOCK:
                if not isinstance(target, CountryTarget):
                    errors.append("geo_block requires a country target")
                else:
                    if not target.simulated:
                        # Real GeoIP is lookup and preview only: enforcement would need
                        # network-granular aliases and rules that do not exist (ADR-033).
                        errors.append(
                            "real-country enforcement is not implemented; "
                            "use the GeoIP preview (ADR-033)"
                        )
                    if target.simulated:
                        errors += self._check_simulated_geo(target)
                        notes.append("SIMULATED geography: lab addresses mapped synthetically")
                errors += self._check_duration(intent.duration_s)

        if active_count >= s.max_active_policies:
            errors.append(f"active policy limit {s.max_active_policies} reached")

        auto = (
            mode is OperatingMode.AUTO
            and intent.origin is PolicyOrigin.AI
            and intent.kind in s.auto_kinds
            and (intent.duration_s or 0) <= s.max_auto_duration_s
            and not degraded_telemetry
        )
        if mode is OperatingMode.AUTO and intent.origin is PolicyOrigin.AI and not auto:
            if degraded_telemetry:
                notes.append("telemetry degraded: automatic enforcement suspended")
            else:
                notes.append("outside automatic bounds: requires approval")
        if auto and intent.kind is not PolicyKind.WATCH:
            window_start = now - timedelta(minutes=1)
            while self._auto_log and self._auto_log[0] < window_start:
                self._auto_log.popleft()
            if len(self._auto_log) >= s.max_auto_actions_per_minute:
                auto = False
                notes.append("automatic action rate limit reached: requires approval")
        return Verdict(ok=not errors, errors=tuple(errors), notes=tuple(notes), auto_eligible=auto)

    def record_auto(self, now: datetime) -> None:
        self._auto_log.append(now)

    def _check_source(self, target: SourceTarget) -> list[str]:
        ip = target.source_ip
        errs = []
        if ip.is_unspecified or ip.is_multicast or ip.is_loopback or ip.is_link_local:
            errs.append(f"{ip} is not a valid unicast host")
        for p in self.cfg.safety.protected:
            if ip in p.network:
                errs.append(f"{ip} is protected ({p.reason})")
        if not any(ip in net for net in self.cfg.client_networks()):
            errs.append(f"{ip} is outside the configured client zones")
        return errs

    def geo_members(self, target: CountryTarget) -> frozenset[IPv4Address]:
        """Client addresses a (simulated) country policy covers; protected ones never."""
        if not target.simulated:
            return frozenset()  # real GeoIP is not available in this lab
        mapped = self.cfg.geo_simulation.get(target.country_code, ())
        return frozenset(ip for ip in mapped if not self._check_source(SourceTarget(source_ip=ip)))

    def _check_simulated_geo(self, t: CountryTarget) -> list[str]:
        errs: list[str] = []
        if t.country_code not in self.cfg.geo_simulation:
            errs.append(f"no simulated mapping for {t.country_code} in geo_simulation")
        if t.direction != "inbound":
            errs.append(
                "only inbound country policies exist in the lab: the protected services "
                "never initiate connections to client zones"
            )
        mapped = self.cfg.geo_simulation.get(t.country_code, ())
        for ip in mapped:
            errs += [f"geo mapping: {e}" for e in self._check_source(SourceTarget(source_ip=ip))]
        return errs

    def _check_duration(self, duration: int | None) -> list[str]:
        s = self.cfg.safety
        if duration is None:
            return ["a duration is required"]
        if not s.min_duration_s <= duration <= s.max_duration_s:
            return [f"duration {duration}s outside [{s.min_duration_s}, {s.max_duration_s}]"]
        return []

    def _check_contract(self, app_id: str, c: ContractTarget) -> list[str]:
        app = self.cfg.application(app_id)
        decl = next((r for r in app.routes if r.route == c.route), None)
        if decl is None:
            return [f"route {c.route} is not declared by the application owner"]
        errs = []
        if not c.allowed_methods:
            errs.append("contract must allow at least one method")
        extra = set(c.allowed_methods) - set(decl.methods)
        if extra:
            errs.append(f"methods {sorted(extra)} are not declared for {c.route}")
        missing = set(decl.methods) - set(c.allowed_methods)
        if missing:
            errs.append(f"contract would block declared methods {sorted(missing)}")
        if decl.content_types and not set(c.allowed_content_types) <= set(decl.content_types):
            errs.append("content types exceed the owner declaration")
        if c.max_body_bytes > GLOBAL_BODY_CEILING:
            errs.append("body limit exceeds the global ceiling")
        if decl.max_body_bytes and c.max_body_bytes < decl.max_body_bytes:
            errs.append("body limit is below the owner-declared maximum (would break clients)")
        return errs
