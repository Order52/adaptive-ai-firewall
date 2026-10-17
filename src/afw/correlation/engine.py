"""Evidence correlation → explainable risk assessment.

Each evidence category contributes bounded points with a recorded reason. The
total is an *evidence score* (0..100), not a probability. Behavioral detectors
(statistical and ML) share one corroboration category because they read the
same features; HISTORY is context and never counts as corroboration.
"""

from __future__ import annotations

import math
from collections import defaultdict, deque
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ipaddress import IPv4Address

from afw.config import RiskConfig
from afw.domain.common import new_id
from afw.domain.detection import DetectionResult, DetectorKind
from afw.domain.events import IdsAlert
from afw.domain.features import FeatureVector
from afw.domain.risk import EvidenceCategory, EvidenceItem, RiskAssessment, RiskBand

CAPS = {
    EvidenceCategory.BEHAVIOR_ML: 35.0,
    EvidenceCategory.BEHAVIOR_STAT: 25.0,
    EvidenceCategory.AUTH: 30.0,
    EvidenceCategory.WAF: 30.0,
    EvidenceCategory.IDS: 25.0,
    EvidenceCategory.HISTORY: 15.0,
}
_BEHAVIOR = {EvidenceCategory.BEHAVIOR_ML, EvidenceCategory.BEHAVIOR_STAT}


def _severity(det: DetectionResult, quantile_span: float) -> float:
    """0..1: how far past the threshold, relative to benign score spread."""
    return max(0.0, min(1.0, (det.score - det.threshold) / max(quantile_span, 1e-9)))


@dataclass
class _History:
    enforced: deque[datetime] = field(default_factory=lambda: deque(maxlen=20))
    high_risk: deque[datetime] = field(default_factory=lambda: deque(maxlen=50))


class CorrelationEngine:
    def __init__(self, risk: RiskConfig, ids_lookback_s: int = 60) -> None:
        self.cfg = risk
        self.ids_lookback = timedelta(seconds=ids_lookback_s)
        self._ids: dict[IPv4Address, deque[IdsAlert]] = defaultdict(lambda: deque(maxlen=200))
        self._history: dict[IPv4Address, _History] = defaultdict(_History)
        self.spans: dict[DetectorKind, float] = {}

    # -- inputs ---------------------------------------------------------------
    def add_ids(self, alert: IdsAlert) -> None:
        self._ids[alert.src_ip].append(alert)

    def note_enforcement(self, source: IPv4Address, at: datetime) -> None:
        self._history[source].enforced.append(at)

    def set_score_span(self, kind: DetectorKind, quantiles: Sequence[float]) -> None:
        if len(quantiles) >= 100:
            self.spans[kind] = max(quantiles[99] - quantiles[50], 1e-6)

    # -- assessment -----------------------------------------------------------
    def assess(
        self,
        fv: FeatureVector,
        detections: Sequence[DetectionResult],
        now: datetime,
        degraded: bool = False,
    ) -> RiskAssessment:
        items: list[EvidenceItem] = []
        items += self._behavior(detections)
        items += self._auth(fv)
        items += self._waf(fv)
        items += self._ids_evidence(fv.source_ip, fv.window_end)
        items += self._history_evidence(fv.source_ip, now)

        totals: dict[EvidenceCategory, float] = defaultdict(float)
        for it in items:
            totals[it.category] += it.points
        score = min(100.0, sum(min(v, CAPS[k]) for k, v in totals.items()))
        cats = {k for k, v in totals.items() if v > 0 and k is not EvidenceCategory.HISTORY}
        corroborating = sorted(
            ({EvidenceCategory.BEHAVIOR_ML} if cats & _BEHAVIOR else set()) | (cats - _BEHAVIOR),
            key=str,
        )
        band = self._band(score)
        if band in (RiskBand.HIGH, RiskBand.CRITICAL):
            self._history[fv.source_ip].high_risk.append(now)
        ml = next((d for d in detections if d.detector is DetectorKind.ISOLATION_FOREST), None)
        any_det = ml or (detections[0] if detections else None)
        return RiskAssessment(
            assessment_id=new_id("risk"),
            app_id=fv.app_id,
            source_ip=fv.source_ip,
            assessed_at=now,
            window_end=fv.window_end,
            score=round(score, 1),
            band=band,
            evidence=tuple(items),
            corroborating_categories=tuple(corroborating),
            model_version=ml.model_version if ml else None,
            profile_version=any_det.profile_version if any_det else None,
            detection_ids=tuple(d.detection_id for d in detections),
            detections=tuple(detections),
            degraded_telemetry=degraded,
        )

    def _band(self, score: float) -> RiskBand:
        c = self.cfg
        if score >= c.escalate:
            return RiskBand.CRITICAL
        if score >= c.block:
            return RiskBand.HIGH
        if score >= c.rate_limit:
            return RiskBand.ELEVATED
        if score >= c.watch:
            return RiskBand.LOW
        return RiskBand.NONE

    def _behavior(self, detections: Sequence[DetectionResult]) -> list[EvidenceItem]:
        out = []
        for d in detections:
            if not d.is_anomalous:
                continue
            sev = _severity(d, self.spans.get(d.detector, 1.0))
            ml = d.detector is not DetectorKind.ROBUST_STATS
            base, extra = (20.0, 15.0) if ml else (15.0, 10.0)
            top = ", ".join(
                f"{c.feature}={c.value:g} (profile median {c.baseline_median:g}, z={c.robust_z:g})"
                for c in d.contributions[:3]
            )
            out.append(
                EvidenceItem(
                    category=EvidenceCategory.BEHAVIOR_ML if ml else EvidenceCategory.BEHAVIOR_STAT,
                    code=f"{d.detector.value}_anomaly",
                    points=round(base + extra * sev, 1),
                    detail=(
                        f"{d.detector.value} score {d.score:.3f} ≥ threshold {d.threshold:.3f} "
                        f"(benign pct {d.benign_percentile:.0f}); top drivers: {top or 'n/a'}"
                    ),
                    observed={
                        "score": d.score,
                        "threshold": d.threshold,
                        "severity": round(sev, 3),
                    },
                    refs=(d.detection_id,),
                )
            )
        return out

    def _auth(self, fv: FeatureVector) -> list[EvidenceItem]:
        fails = fv.evidence.get("auth_failures", 0.0)
        attempts = fv.evidence.get("login_attempts", 0.0)
        users = fv.values.get("distinct_usernames", 0.0)
        if fails < 5 or attempts == 0 or fails / attempts < 0.5:
            return []
        points = 15.0 + min(10.0, fails - 5) + (5.0 if users >= 3 else 0.0)
        return [
            EvidenceItem(
                category=EvidenceCategory.AUTH,
                code="repeated_auth_failure" if users < 3 else "credential_spraying",
                points=points,
                detail=(
                    f"{int(fails)}/{int(attempts)} login attempts failed in "
                    f"{(fv.window_end - fv.window_start).seconds}s across {int(users)} usernames"
                ),
                observed={"failures": fails, "attempts": attempts, "usernames": users},
                refs=fv.request_ids[-10:],
            )
        ]

    def _waf(self, fv: FeatureVector) -> list[EvidenceItem]:
        blocked = fv.evidence.get("waf_blocked", 0.0)
        hits = fv.evidence.get("waf_signal_requests", 0.0)
        if hits == 0:
            return []
        families = {k: v for k, v in fv.evidence.items() if k.startswith("crs_") and v > 0}
        points = 10.0 + 5.0 * min(blocked, 4) + (5.0 if len(families) >= 2 else 0.0)
        return [
            EvidenceItem(
                category=EvidenceCategory.WAF,
                code="crs_blocked" if blocked else "crs_matched",
                points=points,
                detail=(
                    f"OWASP CRS flagged {int(hits)} request(s) (score>=5 or blocked), "
                    f"blocked {int(blocked)}; "
                    f"families: {', '.join(sorted(families)) or 'generic'}; "
                    f"max anomaly {int(fv.evidence.get('waf_max_anomaly', 0))}"
                ),
                observed={k: float(v) for k, v in families.items()} | {"blocked": blocked},
                refs=fv.request_ids[-10:],
            )
        ]

    def _ids_evidence(self, src: IPv4Address, at: datetime) -> list[EvidenceItem]:
        recent = [
            a for a in self._ids.get(src, ()) if at - self.ids_lookback <= a.observed_at <= at
        ]
        if not recent:
            return []
        worst = min(a.severity for a in recent)
        points = {1: 20.0, 2: 12.0, 3: 6.0}.get(worst, 3.0) + min(5.0, len(recent) - 1)
        sigs = sorted({a.signature for a in recent})[:3]
        return [
            EvidenceItem(
                category=EvidenceCategory.IDS,
                code="suricata_alert",
                points=points,
                detail=(
                    f"{len(recent)} Suricata alert(s), worst severity {worst}: {'; '.join(sigs)}"
                ),
                observed={"alerts": len(recent), "worst_severity": worst},
                refs=tuple(a.event_id for a in recent[-5:]),
            )
        ]

    def _history_evidence(self, src: IPv4Address, now: datetime) -> list[EvidenceItem]:
        h = self._history.get(src)
        if h is None:
            return []
        hl = self.cfg.history_half_life_s
        decay = sum(
            math.exp(-math.log(2) * (now - t).total_seconds() / hl) for t in h.enforced
        ) * 10.0 + sum(math.exp(-math.log(2) * (now - t).total_seconds() / hl) for t in h.high_risk)
        if decay < 1.0:
            return []
        return [
            EvidenceItem(
                category=EvidenceCategory.HISTORY,
                code="prior_activity",
                points=round(min(15.0, decay), 1),
                detail=(
                    f"{len(h.enforced)} prior enforcement(s), {len(h.high_risk)} prior high-risk "
                    f"window(s); decayed with {int(hl)}s half-life"
                ),
                observed={"enforcements": len(h.enforced), "high_risk_windows": len(h.high_risk)},
            )
        ]

    def prior_enforcements(self, src: IPv4Address, within: timedelta, now: datetime) -> int:
        h = self._history.get(src)
        return 0 if h is None else sum(1 for t in h.enforced if now - t <= within)
