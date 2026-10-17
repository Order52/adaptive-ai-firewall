"""Detection metrics computed only from separated, labeled runs."""

from __future__ import annotations

import time
from collections.abc import Sequence

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score

from afw.domain.detection import ModelMetrics
from afw.domain.features import FEATURE_NAMES, FeatureVector
from afw.ml.datasets import LabelIndex, Role
from afw.ml.detectors.base import Detector


def labeled_matrix(
    vectors: Sequence[FeatureVector], labels: LabelIndex
) -> tuple[np.ndarray, np.ndarray, list[FeatureVector]]:
    """Rows and y (1=attack) for windows with a known benign/attack label.

    Probe and unlabeled windows are excluded explicitly.
    """
    rows, ys, kept = [], [], []
    for v in vectors:
        role = labels.label(v)
        if role in (Role.BENIGN, Role.ATTACK):
            rows.append(v.as_row())
            ys.append(1 if role is Role.ATTACK else 0)
            kept.append(v)
    return (
        np.array(rows, dtype=float).reshape(-1, len(FEATURE_NAMES)),
        np.array(ys, dtype=int),
        kept,
    )


def threshold_for_fpr(benign_scores: np.ndarray, target_fpr: float) -> float:
    if benign_scores.size == 0:
        raise ValueError("no benign validation scores")
    return float(np.quantile(benign_scores, 1.0 - target_fpr))


def benign_quantiles(benign_scores: np.ndarray) -> tuple[float, ...]:
    return tuple(float(q) for q in np.quantile(benign_scores, np.linspace(0, 1, 101)))


def percentile_rank(score: float, quantiles: Sequence[float]) -> float:
    """Percentile (0..100) of ``score`` among benign validation scores."""
    if not quantiles:
        return 0.0
    idx = int(np.searchsorted(np.asarray(quantiles), score, side="right"))
    return float(min(100, max(0, idx - 1)))


def metrics(scores: np.ndarray, y: np.ndarray, threshold: float) -> ModelMetrics:
    pred = scores >= threshold
    tp = int(np.sum(pred & (y == 1)))
    fp = int(np.sum(pred & (y == 0)))
    fn = int(np.sum(~pred & (y == 1)))
    n_benign, n_attack = int(np.sum(y == 0)), int(np.sum(y == 1))
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / n_attack if n_attack else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall > 0
        else None
    )
    both = n_benign > 0 and n_attack > 0
    del fn
    return ModelMetrics(
        precision=precision,
        recall=recall,
        fpr=fp / n_benign if n_benign else None,
        f1=f1,
        roc_auc=float(roc_auc_score(y, scores)) if both else None,
        pr_auc=float(average_precision_score(y, scores)) if both else None,
        n_benign=n_benign,
        n_attack=n_attack,
    )


def latency_us(detector: Detector, rows: np.ndarray, repeats: int = 200) -> tuple[float, float]:
    if rows.size == 0:
        return 0.0, 0.0
    samples = []
    for i in range(repeats):
        r = rows[i % len(rows)][None, :]
        t0 = time.perf_counter_ns()
        detector.score(r)
        samples.append((time.perf_counter_ns() - t0) / 1000.0)
    arr = np.array(samples)
    return float(arr.mean()), float(np.percentile(arr, 95))
