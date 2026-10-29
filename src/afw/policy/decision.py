"""Proportional response selection from a risk assessment.

The decision engine only *proposes* a typed intent. The validator and the
operating mode decide whether anything is applied.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from afw.config import LabConfig
from afw.domain.policy import PolicyIntent, PolicyKind, PolicyOrigin, RateProfile, SourceTarget
from afw.domain.risk import EvidenceCategory, RiskAssessment
from afw.policy.response import SHARED_ADDRESS_GUARD, response_state

_BEHAVIOR = {EvidenceCategory.BEHAVIOR_ML, EvidenceCategory.BEHAVIOR_STAT}

# A3 login ladder (A3_AUTH_CONTROLS.md §2.2)
LOGIN_CONTROL_S = 900
LOGIN_DENY_MAX_S = 3600
DENY_AFTER_FAILURES = 10


@dataclass(frozen=True)
class LoginContext:
    """The source's login-control situation at decision time.

    ``active``: the profile of a login control in force now, if any; ``failures_since``:
    failed logins answered by the application since it started; ``recent_repeats``:
    login controls on the source that ended within the last hour."""

    active: RateProfile | None = None
    failures_since: int = 0
    recent_repeats: int = 0


class DecisionEngine:
    def __init__(self, cfg: LabConfig) -> None:
        self.cfg = cfg

    def decide(
        self,
        ra: RiskAssessment,
        prior_blocks: int,
        now: datetime,
        accounts_behind: int = 0,
        login: LoginContext | None = None,
    ) -> PolicyIntent | None:
        """``accounts_behind``: distinct accounts recently logged in from the source
        (``response.accounts_behind``); enough of them make the address shared.
        ``login``: the source's login controls; given, authentication evidence is
        answered on the login routes only (A3)."""
        r = self.cfg.risk
        service = self.cfg.application(ra.app_id).service
        cats = set(ra.corroborating_categories)
        evidence_cats = {e.category for e in ra.evidence if e.points > 0}
        behavior_only = cats <= {EvidenceCategory.BEHAVIOR_ML}
        detectors_agree = evidence_cats >= _BEHAVIOR
        need = self.cfg.safety.require_corroboration_for_block
        state = f"state:{response_state(ra, self.cfg).value}"
        shared = accounts_behind >= self.cfg.safety.shared_address_min_accounts

        def intent(kind: PolicyKind, reasons: list[str], **kw: object) -> PolicyIntent:
            return PolicyIntent(
                kind=kind,
                app_id=ra.app_id,
                service=service,
                target=SourceTarget(source_ip=ra.source_ip),
                origin=PolicyOrigin.AI,
                requested_by="adaptive-controller",
                reason_codes=(*reasons, state),
                risk_assessment_id=ra.assessment_id,
                evidence_refs=tuple(ref for e in ra.evidence for ref in e.refs)[:50],
                **kw,
            )

        codes = [e.code for e in ra.evidence if e.points > 0]
        if ra.view == "ids_only":
            # IDS alone never authorizes a traffic-affecting change (M5).
            if ra.score >= r.watch:
                return intent(PolicyKind.WATCH, [*codes, "ids_only_observe"], duration_s=600)
            return None
        if ra.score >= r.block and len(cats) >= need and shared:
            # never block everyone behind a shared address automatically (ADR-043)
            return intent(
                PolicyKind.RATE_LIMIT,
                [*codes, SHARED_ADDRESS_GUARD, f"accounts_behind_{accounts_behind}"],
                duration_s=r.base_block_s,
                rate_profile=RateProfile.STRICT,
            )
        if ra.score >= r.block and len(cats) >= need:
            level = min(5, prior_blocks + (1 if ra.score >= r.escalate else 0))
            duration = int(r.base_block_s * (r.escalation_factor**level))
            duration = min(duration, self.cfg.safety.max_duration_s)
            return intent(
                PolicyKind.SOURCE_BLOCK,
                [*codes, f"escalation_level_{level}"],
                duration_s=duration,
                escalation_level=level,
            )
        auth_scoped = EvidenceCategory.AUTH in cats and not (
            cats - {EvidenceCategory.AUTH, EvidenceCategory.BEHAVIOR_ML}
        )
        if login is not None and (auth_scoped or ra.view == "auth_only"):
            return self._login_ladder(ra, login, shared, codes, intent)
        agree_ok = detectors_agree and self.cfg.safety.behavior_only_rate_limit
        if ra.score >= r.rate_limit and (not behavior_only or agree_ok):
            profile = RateProfile.STRICT if ra.score >= r.block else RateProfile.MODERATE
            return intent(
                PolicyKind.RATE_LIMIT,
                [*codes, "insufficient_corroboration_for_block"] if ra.score >= r.block else codes,
                duration_s=r.base_block_s,
                rate_profile=profile,
            )
        if ra.score >= r.watch:
            # An anomaly alone never authorizes a traffic-affecting change.
            return intent(PolicyKind.WATCH, [*codes, "anomaly_only_observe"], duration_s=600)
        return None

    def _login_ladder(
        self,
        ra: RiskAssessment,
        login: LoginContext,
        shared: bool,
        codes: list[str],
        make: Callable[..., PolicyIntent],
    ) -> PolicyIntent | None:
        """Authentication evidence alone: throttle the login routes, deny them if the
        guessing goes on, never restrict the rest of the site (A3 §2.2)."""
        tags = [*codes, "login_scope_only"] + (["shared_address"] if shared else [])
        if login.active is RateProfile.LOGIN_DENY:
            return None
        if login.active is RateProfile.LOGIN_THROTTLE:
            if login.failures_since < DENY_AFTER_FAILURES:
                return None
            reason = f"failures_during_throttle_{login.failures_since}"
            return make(
                PolicyKind.LOGIN_CONTROL,
                [*tags, reason],
                duration_s=LOGIN_CONTROL_S,
                rate_profile=RateProfile.LOGIN_DENY,
            )
        if login.recent_repeats > 0:
            duration = min(LOGIN_DENY_MAX_S, LOGIN_CONTROL_S * 2 ** (login.recent_repeats - 1))
            return make(
                PolicyKind.LOGIN_CONTROL,
                [*tags, f"repeat_{login.recent_repeats}"],
                duration_s=duration,
                rate_profile=RateProfile.LOGIN_DENY,
                escalation_level=min(5, login.recent_repeats),
            )
        return make(
            PolicyKind.LOGIN_CONTROL,
            tags,
            duration_s=LOGIN_CONTROL_S,
            rate_profile=RateProfile.LOGIN_THROTTLE,
        )
