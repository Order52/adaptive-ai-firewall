"""The closed-loop controller runtime.

ingest ─► correlate ─► windows ─► inference ─► correlation/risk ─► decision ─► policy service
                                     │                                   │
                                     └──────► shadow adaptation ◄────────┘ (reputation)
"""

from __future__ import annotations

import queue
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ipaddress import IPv4Address

import structlog

from afw.config import LabConfig
from afw.correlation.engine import CorrelationEngine
from afw.domain.common import utcnow
from afw.domain.detection import DetectionResult, DetectorKind
from afw.domain.events import HttpObservation
from afw.domain.features import FeatureVector
from afw.domain.network import NetworkEvent
from afw.domain.policy import Policy, PolicyKind, SourceTarget
from afw.domain.risk import EvidenceCategory, RiskAssessment, RiskBand
from afw.features.extract import EndpointCatalog
from afw.features.windows import SlidingWindows
from afw.ml.inference import InferenceEngine, Strategy
from afw.persistence.repositories import (
    SqlAdaptationRepository,
    SqlAnalysisRepository,
    SqlEventRepository,
)
from afw.policy.decision import DecisionEngine
from afw.policy.service import PolicyService
from afw.profiling.adaptation import DriftMonitor, PersistentReputation, SourceReputation
from afw.services.challenger import ChallengerLifecycle
from afw.services.learning import LearningService
from afw.services.shadow import ShadowLearner
from afw.telemetry.correlator import RequestCorrelator, to_ids_alert
from afw.telemetry.parsers.lines import (
    ParseError,
    classify,
    is_network_event,
    parse_app,
    parse_suricata,
    parse_suricata_net,
    parse_waf_access,
    parse_waf_audit,
)
from afw.telemetry.receiver import Line
from afw.telemetry.routes import RouteMatcher
from afw.telemetry.stats import TelemetryStats

log = structlog.get_logger(__name__)
NET_PENDING_MAX = 50_000  # network events buffered between ticks (~1 s of a busy feed x 100)
IDS_ONLY_EVERY = timedelta(seconds=60)
HEARTBEAT_STALE_S = (
    150  # sensors send one every 30 s  # re-assess an IDS-only source at most this often
)
WATCH_RETENTION = timedelta(days=7)
_ROLE_OF_KIND = {
    "afw-waf-access": "waf",
    "afw-waf-audit": "waf",
    "afw-app": "app",
    "suricata": "ids",
}


@dataclass
class LiveSource:
    source_ip: IPv4Address
    app_id: str
    last_seen: datetime
    risk: RiskAssessment
    features: FeatureVector
    detections: list[DetectionResult] = field(default_factory=list)


class Controller:
    def __init__(
        self,
        cfg: LabConfig,
        stats: TelemetryStats,
        events: SqlEventRepository,
        analysis: SqlAnalysisRepository,
        adaptation: SqlAdaptationRepository,
        learning: LearningService,
        policies: PolicyService,
        clock: Callable[[], datetime] = utcnow,
        reputation: PersistentReputation | SourceReputation | None = None,
        shadow: ShadowLearner | None = None,
        lifecycle: ChallengerLifecycle | None = None,
    ) -> None:
        self.cfg = cfg
        self.stats = stats
        self.events = events
        self.analysis = analysis
        self.adaptation_repo = adaptation
        self.learning = learning
        self.policies = policies
        self.clock = clock
        self.app_id = cfg.applications[0].app_id
        matchers = {a.app_id: RouteMatcher(r.route for r in a.routes) for a in cfg.applications}
        self.correlator = RequestCorrelator(
            default_app=self.app_id,
            matchers=matchers,
            stats=stats,
            join_wait_s=cfg.telemetry.join_wait_s,
        )
        self.inference = InferenceEngine()
        self.correlation = CorrelationEngine(cfg.risk)
        self.decisions = DecisionEngine(cfg)
        self.reputation = reputation or SourceReputation()
        self.shadow = shadow
        self.lifecycle = lifecycle
        self.windows = SlidingWindows(
            cfg.window, EndpointCatalog(frozenset(), frozenset(), frozenset())
        )
        self.drift: DriftMonitor | None = None
        self.live: dict[IPv4Address, LiveSource] = {}
        self.timeline: deque[dict[str, object]] = deque(maxlen=720)
        self.lines: queue.Queue[Line] | None = None
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.policies.on_enforced = self._on_enforced
        self.last_tick: datetime | None = None
        self.tick_ms: deque[float] = deque(maxlen=120)
        # N1: network events are buffered and stored once per tick (one transaction)
        self._net_pending: list[NetworkEvent] = []
        self._drop_samples: deque[tuple[float, int]] = deque(maxlen=1000)
        self._ids_only_at: dict[IPv4Address, datetime] = {}
        self._started_at: float | None = None  # set by start(): heartbeats expected
        self.model_error: str | None = None  # trusted models could not be loaded

    # ------------------------------------------------------------ model state
    def reload(self) -> bool:
        try:
            loaded = self.learning.load_active(self.app_id)
        except (OSError, ValueError, TypeError) as exc:
            # A trusted model that fails its integrity check is never used, and the
            # previous in-memory models are dropped too (the registry no longer trusts
            # them): detection runs without behavioural models, evidence is degraded so
            # automation pauses, and health shows why. The controller itself keeps
            # running (telemetry, reconciliation, API) instead of crash-looping.
            self.model_error = str(exc)
            self.inference.load_nothing()
            log.error("model_load_failed", app=self.app_id, error=self.model_error)
            return False
        self.model_error = None
        if loaded is None:
            log.warning("no_trusted_profile", app=self.app_id)
            return False
        profile, models = loaded
        self.inference.load(profile, models)
        self.windows.set_catalog(self.learning.catalog(self.app_id, profile))
        for m in models:
            self.correlation.set_score_span(m.record.detector, m.record.benign_score_quantiles)
        if self.shadow is not None:
            hst = next(
                (m for m in models if m.record.detector is DetectorKind.HALF_SPACE_TREES), None
            )
            self.shadow.reload(profile, hst)
        if self.drift is None:
            self.drift = DriftMonitor(profile)
        else:
            self.drift.reset(profile)
        log.info(
            "models_loaded", profile=profile.version, models=[m.record.version for m in models]
        )
        return True

    def set_strategy(self, strategy: Strategy) -> None:
        self.inference.strategy = strategy

    # ---------------------------------------------------------------- ingest
    def ingest_line(self, sender: IPv4Address, line: str, role: str | None = None) -> None:
        """``role`` is the mTLS-authenticated sensor role of the channel, if any."""
        try:
            kind, payload = classify(line)
            if kind == "afw-heartbeat":
                # Liveness only counts on an authenticated channel (M5).
                if role is None:
                    self.stats.inc("heartbeat_unauthenticated")
                else:
                    self.stats.seen(f"heartbeat:{role}")
                return
            if role is not None and _ROLE_OF_KIND.get(kind) != role:
                # An authenticated sensor may only speak for itself (ADR-029).
                self.stats.inc("role_mismatch")
                return
            authed = {"authenticated": role is not None}
            match kind:
                case "afw-waf-access":
                    rec = parse_waf_access(payload, sender).model_copy(
                        update={**authed, "received_at": self.clock()}
                    )
                    self.correlator.add_access(rec)
                    self.stats.seen("waf")
                case "afw-waf-audit":
                    self.correlator.add_audit(parse_waf_audit(payload).model_copy(update=authed))
                    self.stats.seen("waf_audit")
                case "afw-app":
                    self.correlator.add_app(parse_app(payload).model_copy(update=authed))
                    self.stats.seen("app")
                case "suricata" if is_network_event(payload):
                    ev = parse_suricata_net(payload, sensor_id=str(sender)).model_copy(
                        update={"received_at": self.clock()}
                    )
                    self.stats.seen("ids_net")
                    self.stats.inc(f"net_{ev.kind.value}")
                    if len(self._net_pending) < NET_PENDING_MAX:
                        self._net_pending.append(ev)
                    else:
                        self.stats.inc("net_overflow")  # bounded memory; counted, not silent
                case "suricata":
                    alert = to_ids_alert(
                        parse_suricata(payload, sensor_id=str(sender)), self.clock()
                    )
                    self.stats.seen("ids")
                    self.stats.inc("ids_authenticated" if role else "ids_unauthenticated")
                    if not self.events.add_ids_alerts([alert]):
                        self.stats.inc("duplicate_ids_event")  # replayed line: count once
                        return
                    self.correlation.add_ids(alert)
                    self.reputation.taint(alert.src_ip, alert.observed_at, "ids_alert")
                case _:
                    self.stats.inc("ignored")
        except ParseError as exc:
            self.stats.inc(f"parse_error:{exc.reason}")

    def _flush_net(self) -> list[NetworkEvent]:
        if not self._net_pending:
            return []
        batch, self._net_pending = self._net_pending, []
        added = self.events.add_net_events(batch)
        if len(added) < len(batch):
            self.stats.inc("duplicate_net_event", len(batch) - len(added))
        return added

    def ingest_observations(self, obs: list[HttpObservation]) -> None:
        """Feed already-normalized observations (offline replay of recorded runs)."""
        for o in self.events.add_observations(obs):
            self.windows.add(o)

    def degraded(self) -> bool:
        """Evidence is degraded if lines were dropped in the last 60 s, the WAF sensor
        has gone silent while sources are still being tracked, a sensor is stale, or the
        trusted models failed to load."""
        counts = self.stats.snapshot()["counts"]
        assert isinstance(counts, dict)
        drops = int(counts.get("queue_drop", 0)) + int(counts.get("join_overflow", 0))
        now = time.monotonic()
        self._drop_samples.append((now, drops))
        while self._drop_samples and now - self._drop_samples[0][0] > 60:
            self._drop_samples.popleft()
        recent_drop = drops > self._drop_samples[0][1]
        waf_age = self.stats.age("waf")
        silent = waf_age is not None and waf_age > 120 and self.windows.tracked_sources > 0
        return (
            recent_drop
            or silent
            or self.model_error is not None
            or any(h["stale"] for h in self.sensor_health().values())
        )

    def sensor_health(self) -> dict[str, dict[str, object]]:
        """Heartbeat liveness of each mTLS sensor role, once the receiver is running.
        A sensor that never (re)connected since start is stale too: after a restart,
        a stuck sender is otherwise indistinguishable from an idle one (M5 finding)."""
        if self._started_at is None:
            return {}
        uptime = time.monotonic() - self._started_at
        out: dict[str, dict[str, object]] = {}
        # FW01 (role "ids") heartbeats from its watchdog only while Suricata runs, so a
        # stale "ids" entry means a dead IDS or a dead feed, not merely no alerts.
        for role in sorted(set(self.cfg.telemetry.tls_identities.values())):
            age = self.stats.age(f"heartbeat:{role}")
            stale = (age is None and uptime > HEARTBEAT_STALE_S) or (
                age is not None and age > HEARTBEAT_STALE_S
            )
            out[role] = {"heartbeat_age_s": None if age is None else round(age, 1), "stale": stale}
        return out

    # ------------------------------------------------------------- processing
    def tick(self, now: datetime | None = None) -> list[RiskAssessment]:
        """One processing step; deterministic given the ingested input."""
        t0 = time.perf_counter()
        now = now or self.clock()
        obs = self.correlator.flush()
        self._flush_net()
        sensors = set(self.cfg.telemetry.waf_sensor_ips)
        if sensors and obs:
            own = [o for o in obs if o.client_ip in sensors]
            if own:  # helper self-tests, not client behaviour
                self.stats.inc("sensor_self", len(own))
                obs = [o for o in obs if o.client_ip not in sensors]
        if obs:
            # Only observations the store accepted (request_id is UNIQUE): a
            # replayed request id must not be windowed twice.
            accepted = self.events.add_observations(obs)
            if len(accepted) < len(obs):
                self.stats.inc("duplicate_request_id", len(obs) - len(accepted))
            for o in accepted:
                self.windows.add(o)
        out: list[RiskAssessment] = []
        if (
            self.last_tick is None
            or (now - self.last_tick).total_seconds() >= self.cfg.window.hop_s
        ):
            self.last_tick = now
            vectors = self.windows.emit(now)
            degraded = self.degraded()
            for fv in vectors:
                out.append(self._process_window(fv, now, degraded))
            self._record_timeline(now, vectors, out)
            out += self._ids_only(now, {fv.source_ip for fv in vectors}, degraded)
            if self.lifecycle is not None and self.lifecycle.check(self.app_id, now):
                self.reload()  # probation breached: the parent champion is active again
        self.tick_ms.append((time.perf_counter() - t0) * 1000)
        return out

    def _process_window(self, fv: FeatureVector, now: datetime, degraded: bool) -> RiskAssessment:
        detections = self.inference.score(fv)
        ra = self.correlation.assess(fv, detections, now, degraded=degraded)
        if self.lifecycle is not None:
            self.lifecycle.observe(fv.app_id, detections)  # probation counts only
        watched = self.policies.has_active(fv.source_ip, {PolicyKind.WATCH})
        self.analysis.add_features([fv], dataset_id=None)
        for d in detections:
            if d.is_anomalous or watched:
                self.analysis.add_detection(d)
        if ra.score > 0 or watched:
            self.analysis.add_assessment(ra)
        self.live[fv.source_ip] = LiveSource(
            source_ip=fv.source_ip,
            app_id=fv.app_id,
            last_seen=now,
            risk=ra,
            features=fv,
            detections=detections,
        )
        negative = {e.category for e in ra.evidence if e.points > 0} & {
            EvidenceCategory.WAF,
            EvidenceCategory.IDS,
            EvidenceCategory.AUTH,
        }
        if negative:
            self.reputation.taint(fv.source_ip, now, "+".join(sorted(map(str, negative))))
        if self.drift is not None:
            routes = {o for o in self._routes_of(fv)}
            self.drift.observe(fv, ra, routes, self.reputation.is_tainted(fv.source_ip, now))
        self._decide(ra, now, degraded)
        if self.shadow is not None:
            self.shadow.submit(fv, ra)  # shadow only: never influences the decision above
        return ra

    def _ids_only(
        self, now: datetime, http_sources: set[IPv4Address], degraded: bool
    ) -> list[RiskAssessment]:
        """IDS-only view (M5): sources the IDS reports but with no HTTP window now."""
        out = []
        stale = [s for s, at in self._ids_only_at.items() if now - at > 10 * IDS_ONLY_EVERY]
        for s in stale:
            del self._ids_only_at[s]
        protected = [p.network for p in self.cfg.safety.protected]
        for src in self.correlation.ids_sources(now) - http_sources:
            last = self._ids_only_at.get(src)
            if (last and now - last < IDS_ONLY_EVERY) or any(src in n for n in protected):
                continue
            ra = self.correlation.assess_ids_only(self.app_id, src, now)
            if ra is None:
                continue
            self._ids_only_at[src] = now
            self.stats.inc("ids_only_assessment")
            if ra.score > 0:
                self.analysis.add_assessment(ra)
            self._decide(ra, now, degraded)
            out.append(ra)
        return out

    def _routes_of(self, fv: FeatureVector) -> set[str]:
        recent = self.events.recent_observations(limit=60, source_ip=fv.source_ip)
        return {o.route for o in recent if o.observed_at >= fv.window_start}

    def _decide(self, ra: RiskAssessment, now: datetime, degraded: bool) -> None:
        if ra.band is RiskBand.NONE or self.inference.strategy is Strategy.STATIC:
            return
        if self.policies.has_active(ra.source_ip, {PolicyKind.SOURCE_BLOCK}):
            return  # already maximally contained for this service
        prior = self.correlation.prior_enforcements(ra.source_ip, timedelta(hours=6), now)
        intent = self.decisions.decide(ra, prior, now)
        if intent is None:
            return
        if intent.kind is not PolicyKind.SOURCE_BLOCK and self.policies.has_active(
            ra.source_ip, {intent.kind}
        ):
            return
        if intent.kind is not PolicyKind.WATCH:  # observe-only is not suspicion
            self.reputation.taint(ra.source_ip, now, f"policy:{intent.kind.value}")
        self.policies.submit(intent, degraded=degraded or not self.policies.reconciled_since_start)

    def _on_enforced(self, p: Policy) -> None:
        if p.kind is PolicyKind.SOURCE_BLOCK and isinstance(p.intent.target, SourceTarget):
            self.correlation.note_enforcement(
                p.intent.target.source_ip, p.effective_at or self.clock()
            )

    def _record_timeline(
        self, now: datetime, vectors: list[FeatureVector], ras: list[RiskAssessment]
    ) -> None:
        self.timeline.append(
            {
                "t": now.isoformat(),
                "sources": len(vectors),
                "requests": sum(v.n_requests for v in vectors),
                "max_risk": max((r.score for r in ras), default=0.0),
                "anomalous": sum(
                    1
                    for r in ras
                    if any(e.category is EvidenceCategory.BEHAVIOR_ML for e in r.evidence)
                ),
            }
        )

    def check_drift(self, now: datetime | None = None) -> None:
        if self.drift is None:
            return
        report = self.drift.check(self.app_id, now or self.clock())
        if report is not None:
            self.adaptation_repo.add_drift(report)
            log.info("drift_report", signals=report.signals, assessment=report.assessment)

    # --------------------------------------------------------------- threads
    def start(self, lines: queue.Queue[Line] | None) -> None:
        self.lines = lines
        if lines is not None:  # a live receiver: mTLS sensors must heartbeat
            self._started_at = time.monotonic()
        self._spawn("processor", self._process_loop, 1.0)
        self._spawn("reconciler", self.policies.reconcile, 5.0)
        self._spawn("drift", self.check_drift, 30.0)
        self._spawn("retention", self._retention, 3600.0)
        if self.shadow is not None:
            self.shadow.start()

    def _spawn(self, name: str, fn: Callable[[], object], every: float) -> None:
        def loop() -> None:
            while not self._stop.is_set():
                try:
                    fn()
                except Exception:
                    log.exception("loop_error", loop=name)
                self._stop.wait(every)

        th = threading.Thread(target=loop, name=name, daemon=True)
        th.start()
        self._threads.append(th)

    def _process_loop(self) -> None:
        if self.lines is not None:
            for _ in range(5000):
                try:
                    sender, line, role = self.lines.get_nowait()
                except queue.Empty:
                    break
                self.ingest_line(sender, line, role)
        self.tick()

    def _retention(self) -> None:
        self.events.purge_before(self.clock() - WATCH_RETENTION)

    def stop(self) -> None:
        self._stop.set()
        if self.shadow is not None:
            self.shadow.stop()
