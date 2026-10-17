"""Isolation Forest over log-transformed, robust-scaled behavioral features."""

from __future__ import annotations

from typing import ClassVar

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

from afw.domain.detection import DetectorKind
from afw.domain.profiles import BehaviorProfile
from afw.ml.detectors.base import Detector, transform


class IsolationForestDetector(Detector):
    kind: ClassVar[DetectorKind] = DetectorKind.ISOLATION_FOREST

    def __init__(
        self,
        profile: BehaviorProfile,
        n_estimators: int = 200,
        max_samples: int = 256,
        seed: int = 42,
    ) -> None:
        super().__init__(profile)
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.seed = seed
        self.scaler = RobustScaler(quantile_range=(5.0, 95.0))
        self.model = IsolationForest(
            n_estimators=n_estimators,
            max_samples=max_samples,
            contamination="auto",
            random_state=seed,
            n_jobs=1,
        )

    def fit(self, x: np.ndarray) -> None:
        z = self.scaler.fit_transform(transform(x))
        # Features constant in training get scale 1 from RobustScaler; fine.
        self.model.fit(z)

    def score(self, x: np.ndarray) -> np.ndarray:
        z = self.scaler.transform(transform(np.atleast_2d(x)))
        return np.asarray(-self.model.score_samples(z))

    def params(self) -> dict[str, float | int | str | None]:
        return {
            "n_estimators": self.n_estimators,
            "max_samples": self.max_samples,
            "seed": self.seed,
            "scaler": "robust(5,95)+log1p",
        }
