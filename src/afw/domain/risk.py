"""Correlated risk assessments.

The risk score is an additive, capped *evidence score* on 0..100. It is not a
probability and is never presented as one.
"""

from __future__ import annotations

from collections.abc import Set as AbstractSet
from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address

from pydantic import Field

from afw.domain.common import DomainModel
from afw.domain.detection import DetectionResult


class EvidenceCategory(StrEnum):
    BEHAVIOR_ML = "behavior_ml"
    BEHAVIOR_STAT = "behavior_stat"
    WAF = "waf"
    AUTH = "auth"
    IDS = "ids"
    HISTORY = "history"


# Behaviour features computed from the same events as non-behaviour evidence
# (ADR-027). Failed logins drive AUTH evidence *and* these features; failed
# logins (401) and WAF blocks (403) both land in client_err_frac. A behaviour
# detection corroborates such evidence only if it stays anomalous with the
# listed features occluded (see DetectionResult.independent_of). IDS evidence
# comes from a separate sensor and shares no behaviour features.
EVIDENCE_FEATURES: dict[EvidenceCategory, frozenset[str]] = {
    EvidenceCategory.AUTH: frozenset(
        {"login_rate", "auth_fail_frac", "distinct_usernames", "client_err_frac"}
    ),
    EvidenceCategory.WAF: frozenset({"client_err_frac"}),
}


def independence_key(categories: AbstractSet[EvidenceCategory]) -> str:
    """Key into DetectionResult.independent_of for a set of present categories."""
    return "+".join(sorted(c.value for c in categories if c in EVIDENCE_FEATURES))


class RiskBand(StrEnum):
    NONE = "none"
    LOW = "low"
    ELEVATED = "elevated"
    HIGH = "high"
    CRITICAL = "critical"


class EvidenceItem(DomainModel):
    category: EvidenceCategory
    code: str
    points: float = Field(ge=0)
    detail: str
    observed: dict[str, float | str | int] = Field(default_factory=dict)
    refs: tuple[str, ...] = ()


class RiskAssessment(DomainModel):
    assessment_id: str
    app_id: str
    source_ip: IPv4Address
    assessed_at: datetime
    window_end: datetime
    score: float = Field(ge=0, le=100)
    band: RiskBand
    evidence: tuple[EvidenceItem, ...]
    corroborating_categories: tuple[EvidenceCategory, ...]
    model_version: str | None
    profile_version: int | None
    detection_ids: tuple[str, ...] = ()
    detections: tuple[DetectionResult, ...] = Field(
        default=(),
        description="Full detector outputs (incl. occlusion attributions) snapshotted "
        "at decision time so the explanation stays self-contained after the "
        "detections table is pruned by retention.",
    )
    degraded_telemetry: bool = False
    discounted_categories: tuple[EvidenceCategory, ...] = Field(
        default=(),
        description="Categories present but NOT counted as independent corroboration "
        "because they derive from the same events as other evidence (ADR-027).",
    )
    view: str = Field(
        default="http",
        description="'http': a per-source HTTP window; 'ids_only': IDS alerts from a "
        "source with no HTTP traffic in the window (observe-only, M5)",
    )

    @property
    def independent_evidence(self) -> int:
        return len(self.corroborating_categories)
