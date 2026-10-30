"""Common detector interface, preprocessing and model-faithful attribution."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import ClassVar

import numpy as np

from afw.domain.detection import DetectorKind, FeatureContribution
from afw.domain.features import FEATURE_NAMES, FEATURES
from afw.domain.profiles import BehaviorProfile

LOG_MASK = np.array([f.log_scale for f in FEATURES])


def transform(x: np.ndarray) -> np.ndarray:
    """log1p on heavy-tailed rate/count features (applied identically everywhere)."""
    out = np.array(x, dtype=float, copy=True)
    out[..., LOG_MASK] = np.log1p(np.clip(out[..., LOG_MASK], 0, None))
    return out


class Detector(ABC):
    """Unsupervised anomaly detector over FEATURE_NAMES rows.

    Higher ``score`` means more anomalous. Detectors are trained only on benign
    windows; attack data is never used for fitting.
    """

    kind: ClassVar[DetectorKind]

    def __init__(self, profile: BehaviorProfile) -> None:
        self.profile_version = profile.version
        self.medians = np.array([profile.features[n].median for n in FEATURE_NAMES])
        self.q99 = np.array([profile.features[n].q99 for n in FEATURE_NAMES])
        mads = np.array([profile.features[n].mad for n in FEATURE_NAMES]) * 1.4826
        self.scales = np.maximum.reduce([mads, np.abs(self.medians) * 0.10, _ABS_FLOORS])

    @abstractmethod
    def fit(self, x: np.ndarray) -> None: ...

    @abstractmethod
    def score(self, x: np.ndarray) -> np.ndarray: ...

    def params(self) -> dict[str, float | int | str | None]:
        return {}

    def robust_z(self, row: np.ndarray) -> np.ndarray:
        z: np.ndarray = (row - self.medians) / self.scales
        return z

    def anomalous_without(self, row: np.ndarray, features: Iterable[str], threshold: float) -> bool:
        """Counterfactual: still >= threshold with ``features`` set to the profile median?"""
        occluded = np.array(row, dtype=float, copy=True)
        for name in features:
            i = FEATURE_NAMES.index(name)
            occluded[i] = self.medians[i]
        return bool(self.score(occluded[None, :])[0] >= threshold)

    def explain(self, row: np.ndarray, top_k: int = 5) -> tuple[FeatureContribution, ...]:
        """Occlusion attribution: score drop when a feature is set to its profile median."""
        base = float(self.score(row[None, :])[0])
        occluded = np.repeat(row[None, :], len(FEATURE_NAMES), axis=0)
        idx = np.arange(len(FEATURE_NAMES))
        occluded[idx, idx] = self.medians
        deltas = base - self.score(occluded)
        z = self.robust_z(row)
        order = np.argsort(-deltas)[:top_k]
        return tuple(
            FeatureContribution(
                feature=FEATURE_NAMES[i],
                value=round(float(row[i]), 4),
                baseline_median=round(float(self.medians[i]), 4),
                baseline_q99=round(float(self.q99[i]), 4),
                robust_z=round(float(z[i]), 2),
                score_delta=round(float(deltas[i]), 4),
            )
            for i in order
            if deltas[i] > 0
        )


# Absolute floors keep a near-constant benign feature (MAD = 0) from turning
# tiny deviations into huge z-scores. Order follows FEATURE_NAMES.
_ABS_FLOORS = np.array(
    [
        0.05,  # req_rate (req/s)
        1.0,  # route_count
        0.25,  # route_entropy
        0.05,  # unknown_route_frac
        0.05,  # novel_method_frac
        0.10,  # write_frac
        0.05,  # client_err_frac
        0.02,  # server_err_frac
        1.0,  # login_rate (per min)
        0.10,  # auth_fail_frac
        1.0,  # distinct_usernames
        64.0,  # req_bytes_p95
        0.25,  # interarrival_cv
    ]
)
assert len(_ABS_FLOORS) == len(FEATURE_NAMES)
