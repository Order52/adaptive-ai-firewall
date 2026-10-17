"""Explanations assembled strictly from recorded data (no generated prose).

Answers, for a policy decision: what happened, why it was suspicious, which
evidence contributed, which model/profile were used, what response was chosen
and why, whether it was enforced and verified, and whether legitimate traffic
kept working.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from afw.domain.policy import Policy, SourceTarget
from afw.persistence.repositories import SqlAnalysisRepository, SqlEventRepository


def explain_policy(
    p: Policy, analysis: SqlAnalysisRepository, events: SqlEventRepository
) -> dict[str, Any]:
    ra = (
        analysis.get_assessment(p.intent.risk_assessment_id)
        if p.intent.risk_assessment_id
        else None
    )
    detections = []
    if ra is not None:
        # Prefer the detections snapshotted onto the assessment (self-contained,
        # survives the detections-table retention purge). Fall back to the table
        # for assessments recorded before snapshotting was added.
        if ra.detections:
            detections = list(ra.detections)
        else:
            wanted = set(ra.detection_ids)
            detections = [d for d in analysis.recent_detections(2000) if d.detection_id in wanted]

    legit: dict[str, Any] = {"probe": p.verification.get("legitimate_ok", "not run")}
    if p.effective_at is not None:
        window = events.observations_between(
            p.intent.app_id, p.effective_at, p.effective_at + timedelta(minutes=2)
        )
        target = p.intent.target.source_ip if isinstance(p.intent.target, SourceTarget) else None
        others = [o for o in window if o.client_ip != target]
        ok = [o for o in others if o.status < 400 or o.status == 401]
        legit |= {
            "other_sources_requests_2min": len(others),
            "other_sources_success_ratio": round(len(ok) / len(others), 4) if others else None,
            "target_requests_after_enforcement": sum(1 for o in window if o.client_ip == target),
        }

    return {
        "policy_id": p.policy_id,
        "what_happened": None
        if ra is None
        else {
            "source": str(ra.source_ip),
            "application": ra.app_id,
            "window_end": ra.window_end.isoformat(),
            "risk_score": ra.score,
            "risk_band": ra.band,
            "score_semantics": "additive capped evidence score 0-100; NOT a probability",
        },
        "why_suspicious": []
        if ra is None
        else [
            {"category": e.category, "code": e.code, "points": e.points, "detail": e.detail}
            for e in ra.evidence
        ],
        "contributing_features": [
            {
                "detector": d.detector,
                "score": d.score,
                "threshold": d.threshold,
                "benign_percentile": d.benign_percentile,
                "contributions": [c.model_dump() for c in d.contributions],
                "reason_codes": d.reason_codes,
            }
            for d in detections
        ],
        "model_and_profile": None
        if ra is None
        else {
            "model_version": ra.model_version,
            "profile_version": ra.profile_version,
            "independent_evidence_categories": ra.corroborating_categories,
            "telemetry_degraded": ra.degraded_telemetry,
        },
        "response": {
            "kind": p.kind,
            "target": p.intent.target.model_dump(mode="json"),
            "duration_s": p.intent.duration_s,
            "escalation_level": p.intent.escalation_level,
            "reason_codes": p.intent.reason_codes,
            "mode_at_creation": p.mode_at_creation,
            "origin": p.intent.origin,
            "validation_notes": p.validation_notes,
            "approved_by": p.approved_by,
        },
        "enforcement": {
            "state": p.state,
            "backend": p.enforcement_backend,
            "verification": p.verification,
            "effective_at": p.effective_at.isoformat() if p.effective_at else None,
            "expires_at": p.expires_at.isoformat() if p.expires_at else None,
            "history": [h.model_dump(mode="json") for h in p.history],
        },
        "legitimate_traffic": legit,
    }
