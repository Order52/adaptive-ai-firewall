"""Network novelty detector (N2/N4): unfamiliar vs strongly suspicious network activity.

Two one-sided parts on the residual network quantities (``features/network.py``):

* **Calibrated (learned):** each quantity's benign upper quantile at ``1 - alpha/k``
  (Bonferroni over the k quantities), fitted on trusted benign windows. Exceeding it
  means *unfamiliar*: not seen at that level in legitimate traffic. It says nothing
  about intent and is never treated as confirmed malice.
* **Ceilings (fixed):** attack-sized levels chosen from protocol semantics, not data
  (e.g. 15 distinct ports on one host within 60 s is a port scan whatever the benign
  data says). Calibration can only lower the effective threshold below a ceiling,
  never raise it, so learning from drifted or poisoned benign data cannot make a
  scan look normal.

A source with no residual activity has no vector and is never scored.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

import numpy as np

from afw.features.network import FEATURE_NAMES, NetworkVector

# Fixed ceilings (per 60 s unless named _300). Rationale in ADR-042.
CEILINGS: Mapping[str, float] = {
    "failed_60": 20,  # unanswered/reset connection attempts
    "dst_ports_60": 15,  # horizontal + vertical port fan-out
    "max_ports_per_host_60": 15,  # vertical scan of one host
    "dst_hosts_60": 10,  # host sweep
    "ssh_flows_60": 10,  # SSH connection attempts (password guessing)
    "dns_nxdomain_60": 20,  # random-name lookups (DGA-like, tunnelling probes)
    "dst_ports_300": 50,  # slow scans spread over minutes
    "ssh_flows_300": 30,
    "failed_300": 60,
}
_UNBOUNDED = float("inf")


@dataclass(frozen=True)
class NetworkVerdict:
    source_ip: str
    window_end: str
    unfamiliar: bool  # some quantity above its benign-calibrated level
    strong: bool  # some quantity at or above a fixed ceiling
    score: float  # max value / effective threshold (>= 1 means unfamiliar)
    reasons: tuple[str, ...]


class NetworkNovelty:
    def __init__(self, alpha: float = 0.01, ceilings: Mapping[str, float] = CEILINGS) -> None:
        self.alpha = alpha
        self.ceilings = np.array([ceilings.get(n, _UNBOUNDED) for n in FEATURE_NAMES])
        self.thresholds = self.ceilings.copy()
        self.n_calibration = 0

    def calibrate(self, benign: Sequence[NetworkVector], min_windows: int = 30) -> None:
        """Fit the calibrated levels on trusted benign windows. Sources with no
        residual activity count as zero vectors, so pass them in as such."""
        if len(benign) < min_windows:
            raise ValueError(f"need at least {min_windows} benign windows, got {len(benign)}")
        x = np.array([v.as_row() for v in benign], dtype=float)
        level = 1 - self.alpha / len(FEATURE_NAMES)
        q = np.quantile(x, level, axis=0, method="higher")
        self.thresholds = q
        self.n_calibration = len(benign)

    def effective(self) -> dict[str, float]:
        """The value at which each quantity flags (the lower of the two limits)."""
        eff = np.minimum(self.ceilings, np.nextafter(self.thresholds, np.inf))
        return {n: float(e) for n, e in zip(FEATURE_NAMES, eff, strict=True)}

    def assess(self, v: NetworkVector) -> NetworkVerdict:
        x = np.array(v.as_row(), dtype=float)
        over = x > self.thresholds
        strong = x >= self.ceilings
        eff = np.minimum(self.ceilings, np.maximum(self.thresholds, 1e-9))
        ratio = x / eff
        reasons = tuple(
            f"{n}={x[i]:g} ({'ceiling' if strong[i] else 'unfamiliar'} at {eff[i]:g})"
            for i, n in enumerate(FEATURE_NAMES)
            if over[i] or strong[i]
        )
        return NetworkVerdict(
            source_ip=str(v.source_ip),
            window_end=v.window_end.isoformat(),
            unfamiliar=bool((over | strong).any()),
            strong=bool(strong.any()),
            score=round(float(ratio.max()), 3) if len(ratio) else 0.0,
            reasons=reasons,
        )
