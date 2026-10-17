"""Policy lifecycle orchestration and desired-vs-actual reconciliation.

Single serialized writer (``_lock``). Every state change is journaled in the
policy history and the audit log. Enforcement is level-triggered: each cycle
computes the full desired state from all non-expired owning policies and asks
each backend to converge, then verifies by read-back (and traffic probes where
available) before claiming ENFORCED.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ipaddress import IPv4Address

import structlog

from afw.domain.common import new_id, stable_hash, utcnow
from afw.domain.policy import (
    ContractTarget,
    CountryTarget,
    OperatingMode,
    Policy,
    PolicyIntent,
    PolicyKind,
    PolicyOrigin,
    PolicyState,
    RateProfile,
    SourceTarget,
)
from afw.policy.validator import PolicyValidator, Verdict
from afw.ports.enforcement import (
    ApplyReport,
    DesiredState,
    EnforcementBackend,
    ObservedState,
    TrafficProbe,
)
from afw.ports.repositories import AuditLog, PolicyRepository, SettingsRepository

log = structlog.get_logger(__name__)
S = PolicyState

OWNING_STATES = frozenset({S.APPLYING, S.APPLIED_UNVERIFIED, S.ENFORCED, S.UNKNOWN})
TRACKED_STATES = OWNING_STATES | frozenset(
    {S.VALIDATED, S.PENDING_APPROVAL, S.EXPIRING, S.ROLLBACK_PENDING, S.FAILED}
)
MAX_APPLY_ATTEMPTS = 3


def idempotency_key(intent: PolicyIntent) -> str:
    return stable_hash(
        {
            "kind": intent.kind,
            "app": intent.app_id,
            "service": intent.service,
            "target": intent.target.model_dump(mode="json"),
            "level": intent.escalation_level,
            "rate": intent.rate_profile,
        }
    )[:32]


class PolicyError(ValueError):
    pass


@dataclass
class ReconcileReport:
    at: datetime
    reports: list[ApplyReport] = field(default_factory=list)
    observed: list[ObservedState] = field(default_factory=list)
    transitions: list[tuple[str, str, str]] = field(default_factory=list)
    heartbeat: bool = False


class PolicyService:
    def __init__(
        self,
        repo: PolicyRepository,
        validator: PolicyValidator,
        backends: Iterable[EnforcementBackend],
        settings: SettingsRepository,
        audit: AuditLog,
        probe: TrafficProbe | None = None,
        clock: Callable[[], datetime] = utcnow,
        on_enforced: Callable[[Policy], None] | None = None,
    ) -> None:
        self.repo = repo
        self.validator = validator
        self.backends = list(backends)
        self.settings = settings
        self.audit = audit
        self.probe = probe
        self.clock = clock
        self.on_enforced = on_enforced
        self._lock = threading.RLock()
        self.reconciled_since_start = False
        self._attempts: dict[str, int] = {}
        self.last_report: ReconcileReport | None = None

    # ---------------------------------------------------------------- queries
    def backend_for(self, kind: PolicyKind) -> EnforcementBackend | None:
        return next((b for b in self.backends if kind in b.handles), None)

    def active(self) -> list[Policy]:
        return self.repo.in_states(OWNING_STATES)

    def has_active(self, source: IPv4Address, kinds: set[PolicyKind]) -> bool:
        return any(
            p.kind in kinds
            and isinstance(p.intent.target, SourceTarget)
            and p.intent.target.source_ip == source
            for p in self.repo.in_states(OWNING_STATES | {S.PENDING_APPROVAL, S.VALIDATED})
        )

    # -------------------------------------------------------------- mutations
    def simulate(self, intent: PolicyIntent, degraded: bool = False) -> Verdict:
        mode = self.settings.get_mode()
        return self.validator.validate(
            intent, mode, len(self.active()), self.clock(), degraded_telemetry=degraded
        )

    def submit(self, intent: PolicyIntent, degraded: bool = False) -> Policy:
        with self._lock:
            now = self.clock()
            key = idempotency_key(intent)
            existing = self.repo.by_idempotency_key(key)
            if existing is not None and existing.state in TRACKED_STATES - {S.FAILED}:
                return existing  # duplicate decision: idempotent no-op

            mode = self.settings.get_mode()
            verdict = self.validator.validate(
                intent, mode, len(self.active()), now, degraded_telemetry=degraded
            )
            policy = Policy(
                policy_id=new_id("pol"),
                idempotency_key=key,
                intent=intent,
                state=S.PROPOSED,
                mode_at_creation=mode,
                created_at=now,
                updated_at=now,
                validation_notes=verdict.errors + verdict.notes,
            )
            actor = intent.requested_by
            if not verdict.ok:
                policy = policy.with_state(S.REJECTED, "validator", now, "; ".join(verdict.errors))
                self._save(policy, "rejected")
                return policy

            policy = policy.with_state(S.VALIDATED, "validator", now)
            human = intent.origin in (PolicyOrigin.OPERATOR, PolicyOrigin.MCP)
            if intent.kind is PolicyKind.WATCH:
                policy = self._start_apply(
                    policy, actor, now, "monitoring escalation (no traffic effect)"
                )
            elif human:
                policy = policy.model_copy(update={"approved_by": actor})
                policy = self._start_apply(policy, actor, now, "operator-requested")
            elif mode is OperatingMode.MONITOR:
                policy = policy.activate(now)  # expiry clock for the record only
                self._save(policy, "recorded (monitor mode, not applied)")
                return policy
            elif verdict.auto_eligible:
                self.validator.record_auto(now)
                policy = self._start_apply(policy, "auto", now, "limited-automatic mode")
            else:
                policy = policy.with_state(S.PENDING_APPROVAL, "controller", now)
            self._save(policy, "submitted")
        if policy.state is S.APPLYING:
            self.reconcile()
            policy = self.repo.get(policy.policy_id) or policy
        return policy

    def approve(self, policy_id: str, actor: str) -> Policy:
        with self._lock:
            p = self._get(policy_id)
            if p.state is not S.PENDING_APPROVAL:
                raise PolicyError(f"policy is {p.state}, not pending approval")
            now = self.clock()
            verdict = self.validator.validate(
                p.intent, OperatingMode.ASSISTED, len(self.active()), now
            )
            if not verdict.ok:
                p = p.with_state(S.REJECTED, "validator", now, "; ".join(verdict.errors))
                self._save(p, "rejected at approval")
                return p
            p = p.model_copy(update={"approved_by": actor})
            p = self._start_apply(p, actor, now, "approved")
            self._save(p, "approved")
        self.reconcile()
        return self._get(policy_id)

    def reject(self, policy_id: str, actor: str, reason: str) -> Policy:
        with self._lock:
            p = self._get(policy_id)
            p = p.with_state(S.REJECTED, actor, self.clock(), reason)
            self._save(p, "rejected by operator")
            return p

    def revoke(self, policy_id: str, actor: str, reason: str = "revoked") -> Policy:
        with self._lock:
            p = self._get(policy_id)
            now = self.clock()
            if p.state in (S.VALIDATED, S.PENDING_APPROVAL):
                p = p.with_state(
                    S.EXPIRED if p.state is S.VALIDATED else S.REJECTED, actor, now, reason
                )
                self._save(p, "withdrawn")
                return p
            p = p.with_state(S.ROLLBACK_PENDING, actor, now, reason)
            self._save(p, "rollback requested")
        self.reconcile()
        return self._get(policy_id)

    # --------------------------------------------------------- reconciliation
    def desired_state(self, now: datetime) -> DesiredState:
        blocked: set[IPv4Address] = set()
        denied: set[IPv4Address] = set()
        rates: dict[IPv4Address, RateProfile] = {}
        contracts: dict[str, ContractTarget] = {}
        for p in self.repo.in_states(OWNING_STATES):
            if p.is_expired(now):
                continue
            t = p.intent.target
            if p.kind is PolicyKind.SOURCE_BLOCK and isinstance(t, SourceTarget):
                blocked.add(t.source_ip)
            elif p.kind is PolicyKind.WAF_DENY and isinstance(t, SourceTarget):
                denied.add(t.source_ip)
            elif p.kind is PolicyKind.RATE_LIMIT and isinstance(t, SourceTarget):
                prof = p.intent.rate_profile or RateProfile.MODERATE
                if rates.get(t.source_ip) is not RateProfile.STRICT:
                    rates[t.source_ip] = prof
            elif p.kind is PolicyKind.GEO_BLOCK and isinstance(t, CountryTarget):
                blocked |= self.validator.geo_members(t)
            elif p.kind is PolicyKind.HTTP_CONTRACT and isinstance(t, ContractTarget):
                cur = contracts.get(t.route)
                if cur is None or t.revision > cur.revision:
                    contracts[t.route] = t
        return DesiredState(
            blocked_sources=frozenset(blocked),
            waf_denied_sources=frozenset(denied),
            rate_limited=rates,
            contracts=tuple(sorted(contracts.values(), key=lambda c: c.route)),
        )

    def reconcile(self) -> ReconcileReport:
        with self._lock:
            now = self.clock()
            report = ReconcileReport(at=now)
            self._sweep_expiry(now, report)
            desired = self.desired_state(now)
            observed: dict[str, ObservedState] = {}
            applied: dict[str, ApplyReport] = {}
            for b in self.backends:
                try:
                    rep = b.reconcile(desired)
                except Exception as exc:  # backend errors must not kill the loop
                    log.warning("backend_reconcile_error", backend=b.name, error=str(exc))
                    rep = ApplyReport(backend=b.name, ok=False, error=str(exc), ambiguous=True)
                applied[b.name] = rep
                report.reports.append(rep)
                try:
                    obs = b.observe()
                except Exception as exc:
                    obs = ObservedState(backend=b.name, reachable=False, error=str(exc))
                observed[b.name] = obs
                report.observed.append(obs)
            self._advance(now, desired, applied, observed, report)
            if all(o.reachable for o in observed.values()):
                self.reconciled_since_start = True
                for b in self.backends:
                    beat = getattr(b, "heartbeat", None)
                    if callable(beat):
                        try:
                            beat()
                            report.heartbeat = True
                        except Exception as exc:
                            log.warning("heartbeat_failed", backend=b.name, error=str(exc))
            self.last_report = report
            return report

    # ---------------------------------------------------------------- helpers
    def _start_apply(self, p: Policy, actor: str, now: datetime, note: str) -> Policy:
        return p.with_state(S.APPLYING, actor, now, note).activate(now)

    def _sweep_expiry(self, now: datetime, report: ReconcileReport) -> None:
        for p in self.repo.in_states(OWNING_STATES | {S.VALIDATED, S.PENDING_APPROVAL}):
            if not p.is_expired(now) and not (
                p.state is S.PENDING_APPROVAL
                and p.intent.duration_s
                and now - p.created_at > timedelta(seconds=p.intent.duration_s)
            ):
                continue
            target = S.EXPIRED if p.state in (S.VALIDATED, S.PENDING_APPROVAL) else S.EXPIRING
            if p.state is S.APPLYING:
                target = S.UNKNOWN  # resolved next cycle, then expired
            self._transition(p, target, "expiry", now, "duration elapsed", report)

    def _observed_has(self, p: Policy, obs: ObservedState) -> bool | None:
        t = p.intent.target
        match p.kind:
            case PolicyKind.GEO_BLOCK:
                if obs.blocked_sources is None or not isinstance(t, CountryTarget):
                    return None
                members = self.validator.geo_members(t)
                return bool(members) and members <= obs.blocked_sources
            case PolicyKind.SOURCE_BLOCK:
                return (
                    None
                    if obs.blocked_sources is None
                    else (isinstance(t, SourceTarget) and t.source_ip in obs.blocked_sources)
                )
            case PolicyKind.WAF_DENY:
                return (
                    None
                    if obs.waf_denied_sources is None
                    else (isinstance(t, SourceTarget) and t.source_ip in obs.waf_denied_sources)
                )
            case PolicyKind.RATE_LIMIT:
                return (
                    None
                    if obs.rate_limited is None
                    else (isinstance(t, SourceTarget) and t.source_ip in obs.rate_limited)
                )
            case PolicyKind.HTTP_CONTRACT:
                return (
                    None
                    if obs.contracts is None
                    else (isinstance(t, ContractTarget) and t in obs.contracts)
                )
            case _:
                return None

    def _desired_has(self, p: Policy, d: DesiredState) -> bool:
        t = p.intent.target
        if isinstance(t, SourceTarget):
            return {
                PolicyKind.SOURCE_BLOCK: t.source_ip in d.blocked_sources,
                PolicyKind.WAF_DENY: t.source_ip in d.waf_denied_sources,
                PolicyKind.RATE_LIMIT: t.source_ip in d.rate_limited,
            }.get(p.kind, False)
        if isinstance(t, ContractTarget):
            return t in d.contracts
        if isinstance(t, CountryTarget) and p.kind is PolicyKind.GEO_BLOCK:
            members = self.validator.geo_members(t)
            return bool(members) and members <= d.blocked_sources
        return False

    def _advance(
        self,
        now: datetime,
        desired: DesiredState,
        applied: dict[str, ApplyReport],
        observed: dict[str, ObservedState],
        report: ReconcileReport,
    ) -> None:
        for p in self.repo.in_states(OWNING_STATES | {S.EXPIRING, S.ROLLBACK_PENDING, S.FAILED}):
            if p.kind is PolicyKind.WATCH:
                if p.state in (S.APPLYING,):
                    p = self._transition(p, S.APPLIED_UNVERIFIED, "controller", now, "", report)
                    self._transition(
                        p,
                        S.ENFORCED,
                        "controller",
                        now,
                        "watchlist active",
                        report,
                        verification={"readback": True, "traffic": "n/a"},
                    )
                elif p.state in (S.EXPIRING, S.ROLLBACK_PENDING):
                    final = S.EXPIRED if p.state is S.EXPIRING else S.ROLLED_BACK
                    self._transition(p, final, "controller", now, "watch ended", report)
                continue
            backend = self.backend_for(p.kind)
            if backend is None:
                if p.state is S.APPLYING:
                    self._transition(p, S.FAILED, "controller", now, "no backend", report)
                continue
            rep, obs = applied.get(backend.name), observed.get(backend.name)
            has = self._observed_has(p, obs) if obs and obs.reachable else None

            if p.state in (S.EXPIRING, S.ROLLBACK_PENDING):
                still_owned = self._desired_has(p, desired)
                if has is False or (has is True and still_owned):
                    final = S.EXPIRED if p.state is S.EXPIRING else S.ROLLED_BACK
                    note = (
                        "removal confirmed by read-back"
                        if has is False
                        else ("still owned by another active policy")
                    )
                    self._transition(p, final, "reconciler", now, note, report)
                elif has is None and rep and rep.ambiguous:
                    pass  # stay; retried next cycle
                continue

            if p.state is S.FAILED:
                if p.is_expired(now):
                    self._transition(p, S.EXPIRED, "expiry", now, "expired while failed", report)
                    continue
                n = self._attempts.get(p.policy_id, 0)
                if n < MAX_APPLY_ATTEMPTS and not p.is_expired(now):
                    self._transition(p, S.APPLYING, "reconciler", now, f"retry {n + 1}", report)
                continue

            if p.state is S.APPLYING:
                if rep is None or rep.ambiguous:
                    self._transition(
                        p, S.UNKNOWN, "reconciler", now, (rep.error or "") if rep else "", report
                    )
                    continue
                if not rep.ok:
                    self._attempts[p.policy_id] = self._attempts.get(p.policy_id, 0) + 1
                    self._transition(
                        p, S.FAILED, "reconciler", now, rep.error or "apply failed", report
                    )
                    continue
                p = self._transition(p, S.APPLIED_UNVERIFIED, "reconciler", now, "applied", report)
                sources = self._block_sources(p)
                if sources:
                    killed = 0
                    for src in sorted(sources):
                        try:
                            killed += backend.kill_states(src)
                        except Exception as exc:
                            killed = -1
                            log.warning("kill_states_failed", error=str(exc))
                            break
                    p = self._store_verification(p, {"states_killed": float(killed)})

            if (
                p.state is S.ENFORCED
                and rep is not None
                and isinstance(p.intent.target, SourceTarget)
                and str(p.intent.target.source_ip) in rep.added
            ):
                # The device had lost this entry (e.g. firewall reboot); desired state restored it.
                p = self._store_verification(p, {"restored_at": now.isoformat()})
                self.audit.record(
                    "reconciler", "policy.restored", p.policy_id, {"backend": backend.name}
                )
                report.transitions.append((p.policy_id, "enforced", "restored"))

            if p.state in (S.APPLIED_UNVERIFIED, S.UNKNOWN, S.ENFORCED):
                if has is True:
                    if p.state is not S.ENFORCED:
                        self._verify_and_enforce(p, now, report)
                elif has is False:
                    # e.g. firewall reboot cleared the alias; desired state re-adds it
                    if p.state is S.ENFORCED:
                        self._transition(
                            p,
                            S.UNKNOWN,
                            "reconciler",
                            now,
                            "read-back missing; re-applying",
                            report,
                        )
                elif p.state is S.ENFORCED and obs is not None and not obs.reachable:
                    self._transition(p, S.UNKNOWN, "reconciler", now, "backend unreachable", report)

    def _block_sources(self, p: Policy) -> frozenset[IPv4Address]:
        t = p.intent.target
        if p.kind is PolicyKind.SOURCE_BLOCK and isinstance(t, SourceTarget):
            return frozenset({t.source_ip})
        if p.kind is PolicyKind.GEO_BLOCK and isinstance(t, CountryTarget):
            return self.validator.geo_members(t)
        return frozenset()

    def _verify_and_enforce(self, p: Policy, now: datetime, report: ReconcileReport) -> None:
        verification: dict[str, str | bool | float] = {"readback": True}
        traffic: bool | None = None
        sources = self._block_sources(p)
        if self.probe is not None and sources:
            # Probe every covered source an agent owns; unknown (None) ones are skipped.
            results = [
                r for r in (self.probe.source_blocked(s) for s in sorted(sources)) if r is not None
            ]
            traffic = all(results) if results else None
            verification["probed_sources"] = float(len(results))
            legit = self.probe.legitimate_ok()
            verification["legitimate_ok"] = "unavailable" if legit is None else legit
            if legit is False:
                traffic = None  # cannot distinguish a block from an outage
                verification["note"] = "legitimate probe failed: service problem, not proof"
        if p.kind in (PolicyKind.RATE_LIMIT, PolicyKind.WAF_DENY, PolicyKind.HTTP_CONTRACT):
            traffic = True  # WAF helper runs positive/negative self-tests before reporting
            verification["traffic"] = "waf_helper_selftest"
        if traffic is None:
            verification.setdefault("traffic", "unverified")
            self._store_verification(p, verification)
            return
        verification["traffic"] = "blocked" if traffic else "NOT blocked"
        if traffic:
            p = self._store_verification(p, verification)
            p = self._transition(p, S.ENFORCED, "reconciler", now, "read-back + traffic", report)
            if self.on_enforced:
                self.on_enforced(p)
        else:
            self._store_verification(p, verification)

    def _store_verification(self, p: Policy, v: dict[str, str | bool | float]) -> Policy:
        p = p.model_copy(update={"verification": {**p.verification, **v}})
        self.repo.save(p)
        return p

    def _transition(
        self,
        p: Policy,
        target: PolicyState,
        actor: str,
        now: datetime,
        note: str,
        report: ReconcileReport,
        verification: dict[str, str | bool | float] | None = None,
    ) -> Policy:
        old = p.state
        p = p.with_state(target, actor, now, note)
        if verification:
            p = p.model_copy(update={"verification": {**p.verification, **verification}})
        self._save(p, f"{old}->{target}")
        report.transitions.append((p.policy_id, str(old), str(target)))
        return p

    def _save(self, p: Policy, action: str) -> None:
        self.repo.save(p)
        self.audit.record(
            actor=p.history[-1].actor if p.history else p.intent.requested_by,
            action=f"policy.{action}",
            subject=p.policy_id,
            detail={
                "kind": p.kind,
                "state": p.state,
                "target": p.intent.target.model_dump(mode="json"),
            },
        )
        log.info("policy", id=p.policy_id, kind=p.kind, state=p.state, action=action)

    def _get(self, policy_id: str) -> Policy:
        p = self.repo.get(policy_id)
        if p is None:
            raise PolicyError(f"unknown policy {policy_id}")
        return p
