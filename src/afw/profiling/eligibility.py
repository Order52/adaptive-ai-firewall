"""Which live windows may ever train the online challenger (ADR-028).

Two stages. Stage 1 runs when the window is produced and rejects what is
demonstrably unsuitable. Survivors wait in quarantine for ``admission_delay``
so that late evidence (IDS alerts, WAF blocks, policies, operator feedback)
can still disqualify them. Stage 2 (in the shadow learner) applies the
time-dependent, population-level controls.

Passing this gate does NOT mean a window is benign: absence of evidence is not
evidence of absence. The gate only removes what is demonstrably suspicious and
bounds how much any one source or burst can influence learning.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network

from afw.domain.features import FeatureVector
from afw.domain.learning import Exclusion
from afw.domain.profiles import BehaviorProfile
from afw.domain.risk import EvidenceCategory, RiskAssessment
from afw.ml.online import malformed

NEGATIVE = frozenset({EvidenceCategory.WAF, EvidenceCategory.IDS, EvidenceCategory.AUTH})
# Attack-like behaviour must never become "normal", whatever the population says.
SENSITIVE = ("auth_fail_frac", "client_err_frac", "distinct_usernames", "login_rate")


@dataclass(frozen=True)
class Candidate:
    fv: FeatureVector
    fingerprint: str
    release_at: datetime
    anomalous: bool  # a trusted (enforcing) detector flagged the window
    signature: frozenset[str] = field(default_factory=frozenset)  # top anomaly drivers


def anomaly_signature(ra: RiskAssessment) -> frozenset[str]:
    """Top-2 driver features of each anomalous trusted detection."""
    out: set[str] = set()
    for d in ra.detections:
        if d.is_anomalous:
            out |= {c.feature for c in d.contributions[:2]}
    return frozenset(out)


@dataclass
class StageOne:
    protected: tuple[IPv4Network, ...]
    sensors: frozenset[IPv4Address]

    @classmethod
    def build(cls, protected: Iterable[IPv4Network], sensors: Iterable[IPv4Address]) -> StageOne:
        return cls(tuple(protected), frozenset(sensors))

    def check(
        self,
        fv: FeatureVector,
        ra: RiskAssessment,
        profile: BehaviorProfile,
        *,
        watermark: datetime | None,
        candidate_end: datetime | None,
        tainted: bool,
        learned: bool,
    ) -> Exclusion | None:
        ev = fv.evidence
        # Windows built before provenance existed count as fully untrusted.
        if ev.get("untrusted_obs", float(fv.n_requests)) > 0:
            return Exclusion.UNVERIFIED
        if ev.get("unjoined_obs", float(fv.n_requests)) > 0:
            return Exclusion.UNJOINED
        if malformed(fv) is not None:
            return Exclusion.MALFORMED
        src = fv.source_ip
        if src in self.sensors or any(src in n for n in self.protected):
            return Exclusion.PROTECTED
        if any(e.category in NEGATIVE and e.points > 0 for e in ra.evidence):
            return Exclusion.NEGATIVE_EVIDENCE
        for name in SENSITIVE:
            if fv.values[name] > profile.features[name].q99:
                return Exclusion.SENSITIVE_RANGE
        if learned or (watermark is not None and fv.window_end <= watermark):
            return Exclusion.DUPLICATE
        if candidate_end is not None and fv.window_start < candidate_end:
            return Exclusion.OVERLAP
        if tainted:
            return Exclusion.TAINTED
        return None
