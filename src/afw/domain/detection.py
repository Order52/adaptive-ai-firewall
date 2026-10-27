"""Detector outputs and model metadata."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address

from pydantic import Field

from afw.domain.common import DomainModel


class DetectorKind(StrEnum):
    ROBUST_STATS = "robust_stats"
    ISOLATION_FOREST = "isolation_forest"
    HALF_SPACE_TREES = "half_space_trees"


class ModelStatus(StrEnum):
    CANDIDATE = "candidate"
    ACTIVE = "active"
    RETIRED = "retired"
    REJECTED = "rejected"


class FeatureContribution(DomainModel):
    """How much one feature moved the score, from genuine model evaluation.

    ``robust_z`` is the deviation from the profile median in MAD units.
    ``score_delta`` is the drop in anomaly score when the feature is replaced by
    the profile median (occlusion), i.e. a model-faithful attribution.
    """

    feature: str
    value: float
    baseline_median: float
    baseline_q99: float
    robust_z: float
    score_delta: float


class DetectionResult(DomainModel):
    detection_id: str
    detector: DetectorKind
    model_version: str
    profile_version: int
    app_id: str
    source_ip: IPv4Address
    window_end: datetime
    n_requests: int
    score: float
    threshold: float
    is_anomalous: bool
    benign_percentile: float = Field(
        ge=0, le=100, description="Rank of the score among benign validation windows"
    )
    contributions: tuple[FeatureContribution, ...] = ()
    reason_codes: tuple[str, ...] = ()
    latency_ms: float = 0.0
    independent_of: tuple[str, ...] = Field(
        default=(),
        description="Evidence-category keys ('auth', 'waf', 'auth+waf') for which the "
        "detection stays anomalous with the features derived from that evidence "
        "occluded to the profile median (ADR-027). Empty = never independent.",
    )


class ModelMetrics(DomainModel):
    precision: float | None = None
    recall: float | None = None
    fpr: float | None = None
    f1: float | None = None
    roc_auc: float | None = None
    pr_auc: float | None = None
    n_benign: int = 0
    n_attack: int = 0
    mean_latency_us: float | None = None
    p95_latency_us: float | None = None
    model_bytes: int | None = None
    peak_rss_mb: float | None = None


class ModelRecord(DomainModel):
    model_id: str
    app_id: str
    detector: DetectorKind
    version: str
    profile_version: int
    status: ModelStatus
    created_at: datetime
    params: dict[str, float | int | str | None]
    threshold: float
    feature_names: tuple[str, ...]
    train_dataset_ids: tuple[str, ...]
    validation_dataset_ids: tuple[str, ...]
    artifact_sha256: str
    artifact_path: str
    validation_metrics: ModelMetrics
    benign_score_quantiles: tuple[float, ...] = Field(
        description="101 quantiles (0..100) of benign validation scores, for percentile ranks"
    )
