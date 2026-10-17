"""River Half-Space Trees: an online anomaly detector.

Used two ways: (1) as a frozen comparator trained on the same benign windows,
(2) as the *shadow* learner that keeps learning from benign-gated live traffic
without ever influencing live decisions until a reviewed promotion.
"""

from __future__ import annotations

import copy
from typing import ClassVar

import numpy as np
from river import anomaly

from afw.domain.detection import DetectorKind
from afw.domain.features import FEATURE_NAMES
from afw.domain.profiles import BehaviorProfile
from afw.ml.detectors.base import Detector, transform


class HalfSpaceTreesDetector(Detector):
    kind: ClassVar[DetectorKind] = DetectorKind.HALF_SPACE_TREES

    def __init__(
        self,
        profile: BehaviorProfile,
        n_trees: int = 25,
        height: int = 10,
        window_size: int = 250,
        seed: int = 42,
    ) -> None:
        super().__init__(profile)
        self.n_trees, self.height, self.window_size, self.seed = n_trees, height, window_size, seed
        lo = transform(np.array([profile.features[n].q01 for n in FEATURE_NAMES]))
        hi = transform(np.array([profile.features[n].q99 for n in FEATURE_NAMES]))
        span = np.maximum(hi - lo, 1e-6)
        # Leave headroom so values beyond benign q99 are still separable.
        self.lo = lo - 0.25 * span
        self.span = span * 3.0
        self.model = anomaly.HalfSpaceTrees(
            n_trees=n_trees, height=height, window_size=window_size, seed=seed
        )

    def _dict(self, row: np.ndarray) -> dict[str, float]:
        scaled = np.clip((transform(row) - self.lo) / self.span, 0.0, 1.0)
        return dict(zip(FEATURE_NAMES, scaled.tolist(), strict=True))

    def fit(self, x: np.ndarray) -> None:
        for row in np.atleast_2d(x):
            self.model.learn_one(self._dict(row))

    def learn_one(self, row: np.ndarray) -> None:
        self.model.learn_one(self._dict(row))

    def score(self, x: np.ndarray) -> np.ndarray:
        return np.array([self.model.score_one(self._dict(r)) for r in np.atleast_2d(x)])

    def frozen_copy(self) -> HalfSpaceTreesDetector:
        return copy.deepcopy(self)

    def params(self) -> dict[str, float | int | str | None]:
        return {
            "n_trees": self.n_trees,
            "height": self.height,
            "window_size": self.window_size,
            "seed": self.seed,
        }
