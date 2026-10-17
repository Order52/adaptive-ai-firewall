"""Correlated risk assessments.

The risk score is an additive, capped *evidence score* on 0..100. It is not a
probability and is never presented as one.
"""

from __future__ import annotations

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

    @property
    def independent_evidence(self) -> int:
        return len(self.corroborating_categories)
