"""Proportional response selection from a risk assessment.

The decision engine only *proposes* a typed intent. The validator and the
operating mode decide whether anything is applied.
"""

from __future__ import annotations

from datetime import datetime

from afw.config import LabConfig
from afw.domain.policy import PolicyIntent, PolicyKind, PolicyOrigin, RateProfile, SourceTarget
from afw.domain.risk import EvidenceCategory, RiskAssessment

_BEHAVIOR = {EvidenceCategory.BEHAVIOR_ML, EvidenceCategory.BEHAVIOR_STAT}


class DecisionEngine:
    def __init__(self, cfg: LabConfig) -> None:
        self.cfg = cfg

    def decide(self, ra: RiskAssessment, prior_blocks: int, now: datetime) -> PolicyIntent | None:
        r = self.cfg.risk
        service = self.cfg.application(ra.app_id).service
        cats = set(ra.corroborating_categories)
        evidence_cats = {e.category for e in ra.evidence if e.points > 0}
        behavior_only = cats <= {EvidenceCategory.BEHAVIOR_ML}
        detectors_agree = evidence_cats >= _BEHAVIOR
        need = self.cfg.safety.require_corroboration_for_block

        def intent(kind: PolicyKind, reasons: list[str], **kw: object) -> PolicyIntent:
            return PolicyIntent(
                kind=kind,
                app_id=ra.app_id,
                service=service,
                target=SourceTarget(source_ip=ra.source_ip),
                origin=PolicyOrigin.AI,
                requested_by="adaptive-controller",
                reason_codes=tuple(reasons),
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
