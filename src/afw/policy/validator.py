"""The single safety gate for every policy, whatever its origin (AI, operator, MCP)."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv4Network

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
from afw.policy.geo import GeoTables
from afw.policy.response import SHARED_ADDRESS_GUARD

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
    geo: GeoTables | None = None
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
                elif target.simulated:
                    errors += self._check_simulated_geo(target)
                    notes.append("SIMULATED geography: lab addresses mapped synthetically")
                else:
                    errs, real_notes = self._check_real_geo(intent, target, now)
                    errors += errs
                    notes += real_notes
                errors += self._check_duration(intent.duration_s)

        if active_count >= s.max_active_policies:
            errors.append(f"active policy limit {s.max_active_policies} reached")

        auto = (
            mode is OperatingMode.AUTO
            and intent.origin is PolicyOrigin.AI
            and intent.kind in s.auto_kinds
            and (intent.duration_s or 0) <= s.max_auto_duration_s
            and not degraded_telemetry
            and SHARED_ADDRESS_GUARD not in intent.reason_codes
        )
        if mode is OperatingMode.AUTO and intent.origin is PolicyOrigin.AI and not auto:
            if SHARED_ADDRESS_GUARD in intent.reason_codes:
                notes.append("shared address: requires human approval")
            elif degraded_telemetry:
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

    def _check_real_geo(
        self, intent: PolicyIntent, t: CountryTarget, now: datetime
    ) -> tuple[list[str], list[str]]:
        """Real-country policies (ADR-036): human-requested, fresh verified database,
        bounded size, never touching lab or protected space."""
        g = self.cfg.geo_enforcement
        if not g.enabled or self.geo is None:
            return ["real-country enforcement is not enabled (geo_enforcement)"], []
        errs: list[str] = []
        if intent.origin is PolicyOrigin.AI:
            errs.append("country policies are operator decisions; the AI never proposes them")
        db = self.geo.db()
        if db is None:
            return [*errs, "no GeoIP database loaded"], []
        status = db.status(now)
        if status.get("stale"):
            errs.append(f"GeoIP database is stale (release {status.get('release')})")
        if t.country_code not in db.countries():
            return [*errs, f"{t.country_code} is not a country in the GeoIP database"], []
        nets = self.geo.networks(t.country_code)
        if not nets:
            errs.append(f"{t.country_code} has no globally routable networks")
        if len(nets) > g.max_networks:
            errs.append(
                f"{t.country_code} has {len(nets)} networks, above the per-direction limit "
                f"{g.max_networks}"
            )
        lab = [z.network for z in self.cfg.zones] + [p.network for p in self.cfg.safety.protected]
        if any(IPv4Network(n).overlaps(z) for n in nets for z in lab):
            errs.append("country networks overlap lab or protected space")
        notes = [
            f"REAL geography: {len(nets)} networks of {t.country_code} "
            f"(DB-IP {status.get('release')})",
        ]
        if t.direction in ("inbound", "both"):
            notes.append(
                "inbound: verified by table read-back only (no real-country traffic "
                "reaches the lab)"
            )
        if t.direction in ("outbound", "both"):
            notes.append(
                "outbound: client zones (USERS, ATTACK) only; servers and MGMT are not covered"
            )
        return errs, notes

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
