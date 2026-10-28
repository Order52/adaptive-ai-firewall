"""Live scoring with the frozen trusted profile and active models."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from enum import StrEnum

import numpy as np

from afw.domain.common import new_id
from afw.domain.detection import DetectionResult, DetectorKind, ModelRecord
from afw.domain.features import FEATURE_NAMES, FeatureVector
from afw.domain.profiles import BehaviorProfile
from afw.domain.risk import EvidenceCategory, independence_key
from afw.ml.detectors.base import Detector
from afw.ml.detectors.robust import RobustStatsDetector
from afw.ml.evaluation import percentile_rank

# Combinations of correlated evidence a behaviour detection is tested against.
_DEPENDENT_SETS = tuple(
    {c for c in combo}
    for combo in (
        (EvidenceCategory.AUTH,),
        (EvidenceCategory.WAF,),
        (EvidenceCategory.AUTH, EvidenceCategory.WAF),
    )
)


def _independent_of(
    det: Detector, row: np.ndarray, threshold: float, fv: FeatureVector | None = None
) -> tuple[str, ...]:
    """Evidence combinations this anomaly is independent of (ADR-027, ADR-039).

    Counterfactual (SV-1): the window is re-scored WITHOUT the requests that produced
    the evidence (``fv.residuals``); nothing left, or a residual scored normal, means
    the anomaly came from those requests. Feature occlusion was shown to call up to
    76 % of such anomalies independent, so it is no longer used: a vector without
    residuals (recorded before ADR-039, or built by hand) is independent of nothing,
    which can only withhold corroboration, never add it."""
    if fv is None or fv.residuals is None:
        return ()
    out = []
    for cats in _DEPENDENT_SETS:
        key = independence_key(cats)
        # only the categories this window has requests for can be removed
        present = sorted(c.value for c in cats if c.value in fv.residuals)
        if not present:
            out.append(key)  # nothing to remove: the anomaly stands as scored
            continue
        rest = fv.residuals["+".join(present)]
        if rest is None:
            continue
        rrow = np.array([rest[n] for n in FEATURE_NAMES], dtype=float)
        if float(det.score(rrow[None, :])[0]) >= threshold:
            out.append(key)
    return tuple(out)


class Strategy(StrEnum):
    """Experimental arms (docs/AI_RESEARCH.md §Evaluation)."""

    STATIC = "static"  # M0: no adaptive detection (firewall/WAF/IDS baseline only)
    STATISTICAL = "statistical"  # M1: robust statistics only
    ML = "ml"  # M2: robust statistics + Isolation Forest


@dataclass
class LoadedModel:
    record: ModelRecord
    detector: Detector


class InferenceEngine:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.profile: BehaviorProfile | None = None
        self.models: dict[DetectorKind, LoadedModel] = {}
        self.strategy = Strategy.ML

    def load(self, profile: BehaviorProfile, models: list[LoadedModel]) -> None:
        with self._lock:
            self.profile = profile
            self.models = {m.record.detector: m for m in models}

    def active_kinds(self) -> list[DetectorKind]:
        match self.strategy:
            case Strategy.STATIC:
                return []
            case Strategy.STATISTICAL:
                return [DetectorKind.ROBUST_STATS]
            case Strategy.ML:
                return [DetectorKind.ROBUST_STATS, DetectorKind.ISOLATION_FOREST]

    def score(self, fv: FeatureVector) -> list[DetectionResult]:
        with self._lock:
            if self.profile is None or fv.app_id != self.profile.app_id:
                return []
            row = np.array(fv.as_row(), dtype=float)
            results = []
            for kind in self.active_kinds():
                loaded = self.models.get(kind)
                if loaded is None:
                    continue
                t0 = time.perf_counter()
                score = float(loaded.detector.score(row[None, :])[0])
                latency = (time.perf_counter() - t0) * 1000
                rec = loaded.record
                anomalous = score >= rec.threshold
                contributions = loaded.detector.explain(row) if anomalous else ()
                det = loaded.detector
                codes = (
                    det.reason_codes(row)
                    if isinstance(det, RobustStatsDetector) and anomalous
                    else tuple(f"{c.feature}_contrib" for c in contributions[:3])
                )
                results.append(
                    DetectionResult(
                        detection_id=new_id("det"),
                        detector=kind,
                        model_version=rec.version,
                        profile_version=self.profile.version,
                        app_id=fv.app_id,
                        source_ip=fv.source_ip,
                        window_end=fv.window_end,
                        n_requests=fv.n_requests,
                        score=round(score, 5),
                        threshold=round(rec.threshold, 5),
                        is_anomalous=anomalous,
                        benign_percentile=percentile_rank(score, rec.benign_score_quantiles),
                        contributions=contributions,
                        reason_codes=codes,
                        latency_ms=round(latency, 3),
                        independent_of=(
                            _independent_of(det, row, rec.threshold, fv) if anomalous else ()
                        ),
                    )
                )
            return results
