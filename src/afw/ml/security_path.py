"""Evidence-weighted fractions and the one-sided security path (P6 §3-4).

* ``wilson_lower``: a fraction observed over few events is weak evidence. One failed
  login out of one is a typo; ten out of ten is not. The one-sided 95 % Wilson lower
  bound turns "rate" into "rate we are confident of".
* ``SecurityPath``: a detector over security-relevant quantities that is one-sided
  (only more than benign is suspicious). Per quantity, the threshold is a calibrated
  benign quantile, but a window is always flagged at a fixed ceiling, so a broader
  benign population, or online adaptation, can never make an attack-sized value
  look normal. Ceilings are configuration, not learned state.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence

import numpy as np

from afw.domain.features import FeatureVector

Z95 = 1.645  # one-sided 95 %


def wilson_lower(count: float, n: float, z: float = Z95) -> float:
    if n <= 0:
        return 0.0
    p = min(1.0, max(0.0, count / n))
    denom = 1 + z * z / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, (centre - margin) / denom)


def _count(fv: FeatureVector, frac: str) -> tuple[float, float]:
    """(events, trials) behind one of the window's fractions."""
    if frac == "auth_fail_frac":
        return fv.evidence.get("auth_failures", 0.0), fv.evidence.get("login_attempts", 0.0)
    n = float(fv.n_requests)
    return round(fv.values[frac] * n), n


WEIGHTED_FRACTIONS = (
    "auth_fail_frac",
    "client_err_frac",
    "server_err_frac",
    "unknown_route_frac",
    "novel_method_frac",
)


def evidence_weighted(fv: FeatureVector) -> FeatureVector:
    """The same window with each fraction replaced by its Wilson lower bound."""
    values = dict(fv.values)
    for f in WEIGHTED_FRACTIONS:
        values[f] = wilson_lower(*_count(fv, f))
    return fv.model_copy(update={"values": values})


QUANTITIES = (
    "auth_failures",
    "auth_fail_lb",
    "distinct_usernames",
    "login_rate",
    "client_errors",
    "unknown_route_lb",
    "novel_method_lb",
)
# Attack-sized values, from the application's semantics (P6 §4), not from data.
CEILINGS: Mapping[str, float] = {
    "auth_failures": 6,
    "auth_fail_lb": 0.6,
    "distinct_usernames": 5,
    "login_rate": 24,
    "client_errors": 25,
    "unknown_route_lb": 0.5,
    "novel_method_lb": 0.5,
}


def quantities(fv: FeatureVector) -> np.ndarray:
    n = float(fv.n_requests)
    return np.array(
        [
            fv.evidence.get("auth_failures", 0.0),
            wilson_lower(*_count(fv, "auth_fail_frac")),
            fv.values["distinct_usernames"],
            fv.values["login_rate"],
            round(fv.values["client_err_frac"] * n),
            wilson_lower(*_count(fv, "unknown_route_frac")),
            wilson_lower(*_count(fv, "novel_method_frac")),
        ],
        dtype=float,
    )


class SecurityPath:
    """Flag when any quantity exceeds its calibrated benign quantile, or reaches its
    ceiling. The calibrated part bounds the window FPR at about ``alpha`` on the
    calibration data (``alpha / k`` per quantity); the ceilings never move."""

    def __init__(self, alpha: float = 0.01, ceilings: Mapping[str, float] = CEILINGS) -> None:
        self.alpha = alpha
        self.ceilings = np.array([ceilings[q] for q in QUANTITIES], dtype=float)
        self.thresholds = self.ceilings.copy()

    def calibrate(self, windows: Sequence[FeatureVector]) -> None:
        if not windows:
            raise ValueError("no calibration windows")
        x = np.array([quantities(w) for w in windows])
        level = 1 - self.alpha / len(QUANTITIES)
        self.thresholds = np.quantile(x, level, axis=0, method="higher")

    def _matrix(self, windows: Sequence[FeatureVector]) -> np.ndarray:
        return np.array([quantities(w) for w in windows]).reshape(-1, len(QUANTITIES))

    def flags(self, windows: Sequence[FeatureVector]) -> np.ndarray:
        x = self._matrix(windows)
        return np.asarray(((x > self.thresholds) | (x >= self.ceilings)).any(axis=1))

    def reasons(self, fv: FeatureVector) -> tuple[str, ...]:
        x = quantities(fv)
        return tuple(
            f"{q}_{'ceiling' if x[i] >= self.ceilings[i] else 'calibrated'}"
            for i, q in enumerate(QUANTITIES)
            if x[i] > self.thresholds[i] or x[i] >= self.ceilings[i]
        )

    def effective(self) -> dict[str, float]:
        """The value at which each quantity flags (the lower of the two limits)."""
        return {
            q: float(min(self.ceilings[i], np.nextafter(self.thresholds[i], np.inf)))
            for i, q in enumerate(QUANTITIES)
        }
