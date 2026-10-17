"""Controlled-adaptation records: drift, shadow learning, feedback, reviews."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address

from pydantic import Field

from afw.domain.common import DomainModel


class DriftSignal(StrEnum):
    FEATURE_SHIFT = "feature_shift"  # ADWIN/PSI change in benign-gated feature stream
    NEW_ENDPOINT = "new_endpoint"  # route absent from trusted profile, widely used
    APP_VERSION_CHANGE = "app_version_change"  # application announced a new version
    FP_RATE_RISE = "fp_rate_rise"  # operator-confirmed false positives accumulating


class DriftReport(DomainModel):
    report_id: str
    app_id: str
    detected_at: datetime
    trusted_profile_version: int
    signals: tuple[DriftSignal, ...]
    details: dict[str, float | str | int]
    distinct_sources: int = Field(description="independent sources exhibiting the drifted behavior")
    assessment: str = Field(
        description="'population' (many sources, consistent with legitimate change) "
        "or 'concentrated' (few sources, treat as suspicious, not as drift)"
    )
    candidate_profile_version: int | None = None


class FeedbackLabel(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN_CHANGE = "benign_change"


class Feedback(DomainModel):
    feedback_id: str
    created_at: datetime
    author: str
    label: FeedbackLabel
    app_id: str
    source_ip: IPv4Address | None = None
    assessment_id: str | None = None
    policy_id: str | None = None
    note: str = ""


class GateCheck(DomainModel):
    name: str
    passed: bool
    value: float | None = None
    limit: float | None = None
    detail: str = ""


class CandidateEvaluation(DomainModel):
    """Evidence that a candidate profile/model is safe to trust."""

    app_id: str
    candidate_profile_version: int
    candidate_model_version: str | None
    evaluated_at: datetime
    checks: tuple[GateCheck, ...]

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.checks)
