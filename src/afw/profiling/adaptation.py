"""Continuous *controlled* adaptation.

    live windows ──► reputation gate ──► shadow stream ──► drift monitor ──► DriftReport
                         │ (excluded: WAF/IDS/auth-abuse    │ (ADWIN per feature,
                         │  evidence, policies, negative    │  new endpoints, app
                         │  feedback — for the whole source)│  versions, FP feedback)
                         ▼                                  ▼
                 source reputation              candidate profile + models
                                                (rebuilt from RAW observations of
                                                 clean sources with the new catalog)
                                                            │
                                                  evaluation gate (anti-poisoning,
                                                  attack regression, FP reduction)
                                                            │
                                                  human review ─► TRUSTED (versioned,
                                                                  rollback possible)

Nothing learned from live traffic affects detection until promoted.
"""

from __future__ import annotations

import threading
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ipaddress import IPv4Address

import numpy as np
from river import drift

from afw.domain.adaptation import DriftReport, DriftSignal, FeedbackLabel
from afw.domain.common import new_id
from afw.domain.features import FEATURE_NAMES, FeatureVector
from afw.domain.profiles import BehaviorProfile
from afw.domain.risk import EvidenceCategory, RiskAssessment
from afw.persistence.repositories import SqlLearningRepository

NEGATIVE_EVIDENCE = {EvidenceCategory.WAF, EvidenceCategory.IDS, EvidenceCategory.AUTH}
SECURITY_SENSITIVE = ("auth_fail_frac", "client_err_frac", "distinct_usernames", "login_rate")


@dataclass
class SourceReputation:
    """Sources ever associated with non-behavioral negative evidence are tainted
    for shadow learning for ``taint_ttl``; their data never trains a profile."""

    taint_ttl: timedelta = timedelta(hours=24)
    _tainted: dict[IPv4Address, tuple[datetime, str]] = field(default_factory=dict)

    def taint(self, src: IPv4Address, at: datetime, reason: str) -> None:
        self._tainted[src] = (at, reason)

    def is_tainted(self, src: IPv4Address, now: datetime) -> str | None:
        entry = self._tainted.get(src)
        if entry is None:
            return None
        if now - entry[0] > self.taint_ttl:
            del self._tainted[src]
            return None
        return entry[1]

    def tainted_sources(self, now: datetime) -> set[IPv4Address]:
        return {s for s in list(self._tainted) if self.is_tainted(s, now)}


class PersistentReputation:
    """Same contract as ``SourceReputation`` but stored in the database, so a
    controller restart does not launder a tainted source (Phase 0 finding).
    Retention is bounded by ``SqlLearningRepository.purge_sources``."""

    def __init__(self, repo: SqlLearningRepository, taint_ttl: timedelta) -> None:
        self.repo = repo
        self.taint_ttl = taint_ttl

    def taint(self, src: IPv4Address, at: datetime, reason: str) -> None:
        self.repo.taint(src, at, at + self.taint_ttl, reason)

    def is_tainted(self, src: IPv4Address, now: datetime) -> str | None:
        rec = self.repo.source(src)
        return rec.taint_reason if rec is not None and rec.tainted(now) else None

    def tainted_sources(self, now: datetime) -> set[IPv4Address]:
        return self.repo.tainted_sources(now)


@dataclass
class DriftConfig:
    min_population: int = 3  # independent sources required to call it drift
    max_source_share: float = 0.5
    adwin_delta: float = 0.002
    shift_scale: float = 2.0  # |new mean - profile median| in profile scale units
    anomaly_rate_window: int = 120
    anomaly_rate_threshold: float = 0.15
    fp_feedback_threshold: int = 3
    report_cooldown: timedelta = timedelta(minutes=10)


class DriftMonitor:
    """Watches the reputation-gated shadow stream of one application."""

    def __init__(self, profile: BehaviorProfile, cfg: DriftConfig | None = None) -> None:
        self.cfg = cfg or DriftConfig()
        self.profile = profile
        self._lock = threading.Lock()
        self.reset(profile)

    def reset(self, profile: BehaviorProfile) -> None:
        self.profile = profile
        self._adwin = {n: drift.ADWIN(delta=self.cfg.adwin_delta) for n in FEATURE_NAMES}
        self._recent: dict[str, deque[float]] = {n: deque(maxlen=200) for n in FEATURE_NAMES}
        self._shifted: dict[str, datetime] = {}
        self._new_routes: dict[str, set[IPv4Address]] = defaultdict(set)
        self._versions: dict[str, set[IPv4Address]] = defaultdict(set)
        self._anomalous: deque[tuple[IPv4Address, bool]] = deque(
            maxlen=self.cfg.anomaly_rate_window
        )
        self._fp_feedback = 0
        self._last_report: datetime | None = None
        self.accepted = 0
        self.rejected: Counter[str] = Counter()

    def observe(
        self, fv: FeatureVector, ra: RiskAssessment, routes: set[str], tainted: str | None
    ) -> None:
        with self._lock:
            negative = {e.category for e in ra.evidence if e.points > 0} & NEGATIVE_EVIDENCE
            if tainted:
                self.rejected[f"tainted:{tainted}"] += 1
                return
            if negative:
                self.rejected["negative_evidence"] += 1
                return
            self.accepted += 1
            behavior_anomalous = any(
                e.category in (EvidenceCategory.BEHAVIOR_ML, EvidenceCategory.BEHAVIOR_STAT)
                for e in ra.evidence
            )
            self._anomalous.append((fv.source_ip, behavior_anomalous))
            known = self.profile.known_routes()
            for r in routes:
                if r not in known:
                    self._new_routes[r].add(fv.source_ip)
            for v in fv.app_versions:
                if v not in self.profile.provenance.app_versions:
                    self._versions[v].add(fv.source_ip)
            for i, name in enumerate(FEATURE_NAMES):
                value = fv.as_row()[i]
                self._recent[name].append(value)
                self._adwin[name].update(value)
                if self._adwin[name].drift_detected:
                    self._shifted[name] = fv.window_end

    def note_feedback(self, label: FeedbackLabel) -> None:
        if label in (FeedbackLabel.FALSE_POSITIVE, FeedbackLabel.BENIGN_CHANGE):
            self._fp_feedback += 1

    def check(self, app_id: str, now: datetime) -> DriftReport | None:
        with self._lock:
            if self._last_report and now - self._last_report < self.cfg.report_cooldown:
                return None
            c = self.cfg
            signals: list[DriftSignal] = []
            details: dict[str, float | str | int] = {}
            sources: set[IPv4Address] = set()

            routes = {r: s for r, s in self._new_routes.items() if len(s) >= c.min_population}
            routes_minor = {r: s for r, s in self._new_routes.items() if len(s) < c.min_population}
            if routes:
                signals.append(DriftSignal.NEW_ENDPOINT)
                details["new_endpoints"] = ", ".join(sorted(routes))
                sources |= {s for ss in routes.values() for s in ss}
            if routes_minor:
                details["concentrated_new_routes"] = ", ".join(sorted(routes_minor)[:10])
            versions = {v: s for v, s in self._versions.items() if len(s) >= c.min_population}
            if versions:
                signals.append(DriftSignal.APP_VERSION_CHANGE)
                details["new_app_versions"] = ", ".join(sorted(versions))
                sources |= {s for ss in versions.values() for s in ss}

            shifted = []
            for name, when in self._shifted.items():
                if now - when > timedelta(minutes=30) or len(self._recent[name]) < 30:
                    continue
                stats = self.profile.features[name]
                scale = max(stats.mad * 1.4826, abs(stats.median) * 0.1, 1e-3)
                recent_mean = float(np.mean(self._recent[name]))
                if abs(recent_mean - stats.median) / scale >= c.shift_scale:
                    shifted.append(name)
                    details[f"shift_{name}"] = round((recent_mean - stats.median) / scale, 2)
            if shifted:
                signals.append(DriftSignal.FEATURE_SHIFT)

            if len(self._anomalous) >= c.anomaly_rate_window // 2:
                flagged = [s for s, a in self._anomalous if a]
                rate = len(flagged) / len(self._anomalous)
                details["shadow_anomaly_rate"] = round(rate, 3)
                if rate >= c.anomaly_rate_threshold:
                    share = Counter(flagged).most_common(1)[0][1] / len(flagged)
                    details["anomaly_max_source_share"] = round(share, 2)
                    sources |= set(flagged)
                    if DriftSignal.FEATURE_SHIFT not in signals:
                        signals.append(DriftSignal.FEATURE_SHIFT)
            if self._fp_feedback >= c.fp_feedback_threshold:
                signals.append(DriftSignal.FP_RATE_RISE)
                details["fp_feedback"] = self._fp_feedback

            if not signals:
                return None
            flagged_all = [s for s, a in self._anomalous if a]
            top_share = (
                Counter(flagged_all).most_common(1)[0][1] / len(flagged_all) if flagged_all else 0.0
            )
            population = len(sources) >= c.min_population and top_share <= c.max_source_share
            self._last_report = now
            return DriftReport(
                report_id=new_id("drift"),
                app_id=app_id,
                detected_at=now,
                trusted_profile_version=self.profile.version,
                signals=tuple(signals),
                details=details,
                distinct_sources=len(sources),
                assessment="population" if population else "concentrated",
            )

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                "accepted_windows": self.accepted,
                "rejected": dict(self.rejected),
                "new_routes": {r: len(s) for r, s in self._new_routes.items()},
                "new_versions": {v: len(s) for v, s in self._versions.items()},
                "shifted_features": sorted(self._shifted),
                "shadow_anomaly_rate": (
                    round(sum(1 for _, a in self._anomalous if a) / len(self._anomalous), 3)
                    if self._anomalous
                    else None
                ),
            }
