"""Train, threshold and register detectors for one application/profile.

Protocol (enforced here):
1. Fit only on benign windows of TRAIN runs.
2. Choose each threshold from benign windows of VALIDATION runs at a target
   false-positive rate. Attack windows in validation runs are used only to
   *report* validation recall, never to tune anything.
3. TEST/HOLDOUT runs are evaluated by ``afw.ml.experiments`` after freezing
   (the M0/M1/M2 offline replay runner), never used to tune anything here.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

import numpy as np

from afw.domain.common import new_id
from afw.domain.detection import DetectorKind, ModelMetrics, ModelRecord, ModelStatus
from afw.domain.features import FEATURE_NAMES, FeatureVector
from afw.domain.profiles import BehaviorProfile
from afw.ml.detectors.base import Detector
from afw.ml.detectors.hst import HalfSpaceTreesDetector
from afw.ml.detectors.iforest import IsolationForestDetector
from afw.ml.detectors.robust import RobustStatsDetector
from afw.ml.evaluation import benign_quantiles, latency_us, metrics, threshold_for_fpr
from afw.ml.registry import ArtifactStore


@dataclass(frozen=True)
class TrainingData:
    train_benign: Sequence[FeatureVector]
    val_benign: Sequence[FeatureVector]
    val_attack: Sequence[FeatureVector]
    train_dataset_ids: tuple[str, ...]
    val_dataset_ids: tuple[str, ...]


def make_detector(
    kind: DetectorKind, profile: BehaviorProfile, n_train: int, seed: int
) -> Detector:
    match kind:
        case DetectorKind.ROBUST_STATS:
            return RobustStatsDetector(profile)
        case DetectorKind.ISOLATION_FOREST:
            return IsolationForestDetector(
                profile, max_samples=min(256, max(16, n_train)), seed=seed
            )
        case DetectorKind.HALF_SPACE_TREES:
            return HalfSpaceTreesDetector(
                profile, window_size=max(25, min(250, n_train // 2)), seed=seed
            )


def _rows(vectors: Sequence[FeatureVector]) -> np.ndarray:
    return np.array([v.as_row() for v in vectors], dtype=float).reshape(-1, len(FEATURE_NAMES))


def train_and_register(
    *,
    profile: BehaviorProfile,
    data: TrainingData,
    store: ArtifactStore,
    kinds: Sequence[DetectorKind],
    target_fpr: float,
    created_at: datetime,
    seed: int = 42,
) -> list[ModelRecord]:
    if set(data.train_dataset_ids) & set(data.val_dataset_ids):
        raise ValueError("train and validation runs overlap")
    x_train = _rows(data.train_benign)
    x_vb = _rows(data.val_benign)
    x_va = _rows(data.val_attack)
    if len(x_train) < 50 or len(x_vb) < 50:
        raise ValueError(
            f"insufficient benign data: train={len(x_train)} validation={len(x_vb)} (need >= 50)"
        )
    records: list[ModelRecord] = []
    for kind in kinds:
        det = make_detector(kind, profile, len(x_train), seed)
        det.fit(x_train)
        s_vb = det.score(x_vb)
        thr = threshold_for_fpr(s_vb, target_fpr)
        y = np.r_[np.zeros(len(x_vb), dtype=int), np.ones(len(x_va), dtype=int)]
        scores = np.r_[s_vb, det.score(x_va)] if len(x_va) else s_vb
        m = metrics(scores, y, thr)
        mean_us, p95_us = latency_us(det, x_vb)
        version = f"{kind.value}-p{profile.version}-{created_at:%Y%m%d%H%M%S}"
        model_id = new_id("mdl")
        path, digest, size = store.save(profile.app_id, model_id, det)
        records.append(
            ModelRecord(
                model_id=model_id,
                app_id=profile.app_id,
                detector=kind,
                version=version,
                profile_version=profile.version,
                status=ModelStatus.CANDIDATE,
                created_at=created_at,
                params={**det.params(), "target_fpr": target_fpr, "n_train": len(x_train)},
                threshold=thr,
                feature_names=FEATURE_NAMES,
                train_dataset_ids=data.train_dataset_ids,
                validation_dataset_ids=data.val_dataset_ids,
                artifact_sha256=digest,
                artifact_path=path,
                validation_metrics=ModelMetrics(
                    **{
                        **m.model_dump(),
                        "mean_latency_us": round(mean_us, 1),
                        "p95_latency_us": round(p95_us, 1),
                        "model_bytes": size,
                    }
                ),
                benign_score_quantiles=benign_quantiles(s_vb),
            )
        )
    return records
