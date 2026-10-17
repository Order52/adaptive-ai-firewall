"""Robust statistical baseline (median/MAD deviation against the profile).

This is the M1 "rule/statistical adaptive" comparator: transparent, no fitting
beyond the profile itself.
"""

from __future__ import annotations

from typing import ClassVar

import numpy as np

from afw.domain.detection import DetectorKind
from afw.domain.features import FEATURE_NAMES
from afw.ml.detectors.base import Detector

# Direction of suspicion per feature: +1 higher is suspicious, 0 both ways.
_DIRECTION = {name: 1 for name in FEATURE_NAMES} | {"interarrival_cv": 0, "route_entropy": 0}
_DIR = np.array([_DIRECTION[n] for n in FEATURE_NAMES])


class RobustStatsDetector(Detector):
    kind: ClassVar[DetectorKind] = DetectorKind.ROBUST_STATS

    def fit(self, x: np.ndarray) -> None:  # profile-derived; nothing to learn
        return None

    def score(self, x: np.ndarray) -> np.ndarray:
        z = (np.atleast_2d(x) - self.medians) / self.scales
        directed = np.where(_DIR > 0, np.clip(z, 0, None), np.abs(z))
        # mean of the 2 largest deviations: a single noisy feature is not enough
        top = np.sort(directed, axis=1)[:, -2:]
        return np.asarray(top.mean(axis=1))

    def reason_codes(self, row: np.ndarray, z_limit: float = 4.0) -> tuple[str, ...]:
        z = self.robust_z(row)
        codes = []
        for i, name in enumerate(FEATURE_NAMES):
            if (_DIR[i] > 0 and z[i] >= z_limit) or (_DIR[i] == 0 and abs(z[i]) >= z_limit):
                codes.append(f"{name}_{'high' if z[i] > 0 else 'low'}")
        return tuple(codes)
