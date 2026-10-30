"""Shadow online learner: gate -> quarantine -> prequential learn -> checkpoint.

Runs on its own thread, fed by a bounded queue (drop-and-count when full), so
the enforcement path never waits for it. Nothing it produces is read by
correlation, decision or policy code: the challenger is shadow-only until M3
adds validated promotion and rollback. See ADR-028.
"""

from __future__ import annotations

import math
import queue
import threading
from collections import Counter, deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path

import numpy as np
import structlog

from afw.config import LabConfig
from afw.domain.common import utcnow
from afw.domain.features import FeatureVector
from afw.domain.learning import (
    ChallengerCheckpoint,
    Exclusion,
    LearnedWindow,
    ShadowScore,
)
from afw.domain.profiles import BehaviorProfile
from afw.domain.risk import RiskAssessment
from afw.ml.detectors.hst import HalfSpaceTreesDetector
from afw.ml.inference import LoadedModel
from afw.ml.online import CheckpointStore, OnlineChallenger, fingerprint
from afw.persistence.repositories import SqlLearningRepository
from afw.ports.repositories import AuditLog
from afw.profiling.eligibility import NEGATIVE, Candidate, StageOne, anomaly_signature

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class _Admitted:
    at: datetime  # window_end
    source: IPv4Address
    signature: frozenset[str]
    scaled: tuple[float, ...] = ()  # set for corroborated anomalous windows only


class ShadowLearner:
    def __init__(
        self,
        cfg: LabConfig,
        repo: SqlLearningRepository,
        store: CheckpointStore,
        audit: AuditLog,
        *,
        policed: Callable[[IPv4Address], bool],
        reported: Callable[[str], set[IPv4Address]],
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.cfg = cfg
        self.lc = cfg.learning
        self.repo = repo
        self.store = store
        self.audit = audit
        self.policed = policed  # any active policy against the source
        self.reported = reported  # sources reported as true positives by operators
        self.clock = clock
        self.stage_one = StageOne.build(
            (p.network for p in cfg.safety.protected), cfg.telemetry.waf_sensor_ips
        )
        self.inbox: queue.Queue[tuple[FeatureVector, RiskAssessment]] = queue.Queue(
            maxsize=self.lc.queue_max
        )
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.app_id = cfg.applications[0].app_id
        self.profile: BehaviorProfile | None = None
        self.champion: LoadedModel | None = None
        self.challenger: OnlineChallenger | None = None
        self.checkpoint: ChallengerCheckpoint | None = None
        self._reset_progress()
        self.excluded: Counter[str] = Counter()
        self.counts: Counter[str] = Counter()

    def _reset_progress(self) -> None:
        self.watermarks: dict[str, datetime] = {}
        self.candidate_end: dict[str, datetime] = {}
        self.quarantine: list[Candidate] = []
        self.unflushed: list[LearnedWindow] = []
        self.admitted: deque[_Admitted] = deque(maxlen=self.lc.share_window)
        # Per-source admission times for the hourly rate cap. Kept apart from the
        # bounded share window: with many sources that deque evicts a source's recent
        # admissions and the cap leaked (found live, P4 2026-10-28).
        self.rate_log: dict[IPv4Address, deque[datetime]] = {}
        self._shadow_buf: list[ShadowScore] = []
        self._last_ckpt_at: datetime | None = None
        self._last_purge: datetime | None = None

    # ------------------------------------------------------------ lifecycle
    def reload(self, profile: BehaviorProfile, champion: LoadedModel | None) -> None:
        """Bind to the trusted profile's HST champion; restore or start a challenger."""
        with self._lock:
            self.checkpoint_now()  # never discard learned-but-unflushed windows
            self.profile = profile
            self.champion = champion
            self.challenger = None
            self.checkpoint = None
            self._reset_progress()
            self._last_ckpt_at = self.clock()  # checkpoint interval counts from binding
            if champion is None or not isinstance(champion.detector, HalfSpaceTreesDetector):
                log.warning("shadow_learner_disabled", reason="no trusted HST champion")
                return
            restored = self.store.restore(self.app_id, champion.record)
            if restored is not None:
                self.challenger, self.checkpoint = restored
                self.watermarks = dict(restored[1].watermarks)
                self.candidate_end = dict(self.watermarks)
                recent = self.repo.learned(self.app_id, self._rate_restore_limit())
                for w in reversed(recent[: self.lc.share_window]):
                    self.admitted.append(_Admitted(w.window_end, w.source_ip, frozenset()))
                if recent:
                    hour = recent[0].window_end - timedelta(hours=1)
                    for w in reversed(recent):
                        if w.window_end > hour:
                            self.rate_log.setdefault(w.source_ip, deque()).append(w.window_end)
                event = "challenger.restore"
            else:
                self.challenger = OnlineChallenger.from_champion(champion.detector, champion.record)
                event = "challenger.fresh"
            self.audit.record(
                "shadow-learner",
                event,
                f"{self.app_id}:{champion.record.version}",
                {
                    "checkpoint": self.checkpoint.checkpoint_id if self.checkpoint else None,
                    "n_learned": self.challenger.n_learned,
                },
            )

    def start(self, every_s: float = 1.0) -> None:
        def loop() -> None:
            while not self._stop.is_set():
                try:
                    self.process()
                except Exception:
                    log.exception("shadow_learner_error")
                self._stop.wait(every_s)

        self._thread = threading.Thread(target=loop, name="shadow-learner", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        with self._lock:
            self.checkpoint_now()

    # --------------------------------------------------------------- input
    def submit(self, fv: FeatureVector, ra: RiskAssessment) -> None:
        """Called from the processor thread; never blocks."""
        if not self.lc.enabled:
            return
        try:
            self.inbox.put_nowait((fv, ra))
        except queue.Full:
            self.counts["queue_drop"] += 1

    # ----------------------------------------------------------- processing
    def process(self, now: datetime | None = None) -> None:
        now = now or self.clock()
        with self._lock:
            while True:
                try:
                    fv, ra = self.inbox.get_nowait()
                except queue.Empty:
                    break
                self._observe(fv, ra, now)
            self._release(now)
            self._maybe_checkpoint(now)
            if self._shadow_buf:
                self.repo.add_shadow(self._shadow_buf)
                self._shadow_buf = []
            self._maybe_purge(now)

    def _reject(self, why: Exclusion) -> None:
        self.excluded[why.value] += 1

    def _observe(self, fv: FeatureVector, ra: RiskAssessment, now: datetime) -> None:
        self.counts["windows"] += 1
        self.repo.touch(fv.source_ip, fv.window_start)  # activity began at window start
        if self.challenger is None or self.champion is None or self.profile is None:
            self._reject(Exclusion.NO_CHALLENGER)
            return
        self._shadow(fv)
        if any(e.category in NEGATIVE and e.points > 0 for e in ra.evidence):
            self.repo.taint(
                fv.source_ip,
                now,
                now + timedelta(seconds=self.lc.taint_ttl_s),
                "negative_evidence",
            )
        src = str(fv.source_ip)
        rec = self.repo.source(fv.source_ip)
        fp = fingerprint(fv)
        why = self.stage_one.check(
            fv,
            ra,
            self.profile,
            watermark=self.watermarks.get(src),
            candidate_end=self.candidate_end.get(src),
            tainted=bool(rec and rec.tainted(now)),
            learned=self.repo.is_learned(fp) or any(w.fingerprint == fp for w in self.unflushed),
        )
        if why is not None:
            self._reject(why)
            return
        if len(self.quarantine) >= self.lc.quarantine_max:
            self._reject(Exclusion.QUARANTINE_FULL)
            return
        anomalous = any(d.is_anomalous for d in ra.detections)
        self.quarantine.append(
            Candidate(
                fv=fv,
                fingerprint=fp,
                release_at=fv.window_end + timedelta(seconds=self.lc.admission_delay_s),
                anomalous=anomalous,
                signature=anomaly_signature(ra) if anomalous else frozenset(),
                scaled=self._scaled(fv) if anomalous else (),
            )
        )
        self.candidate_end[src] = fv.window_end  # tumbling: next candidate starts after
        self.counts["quarantined"] += 1

    def _shadow(self, fv: FeatureVector) -> None:
        assert self.champion is not None and self.challenger is not None
        champ = float(self.champion.detector.score(np.array([fv.as_row()]))[0])
        chal = self.challenger.score(fv)
        thr = self.champion.record.threshold
        self._shadow_buf.append(
            ShadowScore(
                app_id=fv.app_id,
                source_ip=fv.source_ip,
                window_end=fv.window_end,
                champion_score=round(champ, 6),
                champion_anomalous=champ >= thr,
                challenger_score=round(chal, 6),
                challenger_anomalous=chal >= thr,
                challenger_warm=self.challenger.warm,
                n_learned=self.challenger.n_learned,
                threshold=thr,
            )
        )

    # ------------------------------------------------------------- stage 2
    def _release(self, now: datetime) -> None:
        due = sorted(
            (c for c in self.quarantine if c.release_at <= now),
            key=lambda c: (c.fv.window_end, int(c.fv.source_ip)),
        )
        if not due:
            return
        reported = self.reported(self.app_id)
        expiry = timedelta(seconds=self.lc.population_window_s)
        hold: list[Candidate] = []
        ready: list[Candidate] = []
        for c in due:
            src = c.fv.source_ip
            rec = self.repo.source(src)
            if (rec and rec.tainted(now)) or self.policed(src) or src in reported:
                self._drop(c, Exclusion.LATE_TAINT)
                continue
            tenure = timedelta(seconds=self.lc.min_source_tenure_s)
            if rec is None or c.fv.window_start - rec.first_seen < tenure:
                self._drop(c, Exclusion.TENURE)
                continue
            ready.append(c)
        # population: enough distinct sources among recent admissions + this batch
        horizon = now - expiry
        recent = {a.source for a in self.admitted if a.at >= horizon}
        population = recent | {c.fv.source_ip for c in ready}
        for c in ready:
            src = c.fv.source_ip
            if self._rate_exceeded(src, c.fv.window_end):
                self._drop(c, Exclusion.SOURCE_RATE)
                continue
            if self._share_exceeded(src):
                self._drop(c, Exclusion.SOURCE_SHARE)
                continue
            if c.anomalous and not self._anomaly_corroborated(c, horizon):
                self._hold_or_drop(c, hold, now, expiry, Exclusion.CHAMPION_ANOMALOUS)
                continue
            if len(population) < self.lc.min_distinct_sources:
                self._hold_or_drop(c, hold, now, expiry, Exclusion.POPULATION)
                continue
            self._learn(c, now)
        due_ids = {id(c) for c in due}
        self.quarantine = [c for c in self.quarantine if id(c) not in due_ids] + hold

    def _drop(self, c: Candidate, why: Exclusion) -> None:
        self._reject(why)

    def _hold_or_drop(
        self,
        c: Candidate,
        hold: list[Candidate],
        now: datetime,
        expiry: timedelta,
        why: Exclusion,
    ) -> None:
        if now - c.release_at < expiry:
            hold.append(c)
        else:
            self._reject(why)

    def _rate_exceeded(self, src: IPv4Address, at: datetime) -> bool:
        log_ = self.rate_log.get(src)
        if not log_:
            return False
        hour = at - timedelta(hours=1)
        while log_ and log_[0] <= hour:
            log_.popleft()
        return len(log_) >= self.lc.max_windows_per_source_per_hour

    def _rate_restore_limit(self) -> int:
        """Ledger rows to read on restore: enough for every source's last hour."""
        return max(self.lc.share_window, 50 * self.lc.max_windows_per_source_per_hour)

    def _share_exceeded(self, src: IPv4Address) -> bool:
        cap = math.ceil(self.lc.max_source_share * self.lc.share_window)
        return sum(1 for a in self.admitted if a.source == src) >= cap

    def _scaled(self, fv: FeatureVector) -> tuple[float, ...]:
        det = self.champion.detector if self.champion else None
        if not isinstance(det, HalfSpaceTreesDetector):
            return ()
        return tuple(float(x) for x in det.scaled(np.array(fv.as_row(), dtype=float)))

    def _close(self, a: tuple[float, ...], b: tuple[float, ...]) -> bool:
        if not a or not b:
            return False  # unknown position (e.g. restored ledger entry): never a peer
        return max(abs(x - y) for x, y in zip(a, b, strict=True)) <= self.lc.anomaly_max_distance

    def _anomaly_corroborated(self, c: Candidate, horizon: datetime) -> bool:
        """The same anomalous *behaviour* (not merely the same driver names) shown by
        enough distinct clean sources, none dominating."""
        peers = [
            q.fv.source_ip
            for q in self.quarantine
            if q.anomalous and q.fv.window_end >= horizon and self._close(q.scaled, c.scaled)
        ] + [a.source for a in self.admitted if a.at >= horizon and self._close(a.scaled, c.scaled)]
        if not peers:
            return False
        top = Counter(peers).most_common(1)[0][1] / len(peers)
        distinct = len(set(peers))
        return distinct >= self.lc.anomaly_min_sources and top <= self.lc.max_source_share * 2

    def _learn(self, c: Candidate, now: datetime) -> None:
        assert self.challenger is not None and self.champion is not None
        fv = c.fv
        champ = float(self.champion.detector.score(np.array([fv.as_row()]))[0])
        before, warm = self.challenger.score_then_learn(fv)
        src = str(fv.source_ip)
        self.watermarks[src] = max(fv.window_end, self.watermarks.get(src, fv.window_end))
        self.admitted.append(_Admitted(fv.window_end, fv.source_ip, c.signature, c.scaled))
        self.rate_log.setdefault(fv.source_ip, deque()).append(fv.window_end)
        self.unflushed.append(
            LearnedWindow(
                fingerprint=c.fingerprint,
                app_id=fv.app_id,
                source_ip=fv.source_ip,
                window_start=fv.window_start,
                window_end=fv.window_end,
                learned_at=now,
                challenger_score_before=round(before, 6),
                champion_score=round(champ, 6),
                challenger_warm_before=warm,
                n_learned_after=self.challenger.n_learned,
                parent_model_id=self.challenger.parent.model_id,
            )
        )
        self.counts["learned"] += 1
        if c.anomalous:
            self.counts["learned_anomalous_corroborated"] += 1

    # --------------------------------------------------------- persistence
    def _maybe_checkpoint(self, now: datetime) -> None:
        if not self.unflushed:
            return
        due_time = self._last_ckpt_at is None or (now - self._last_ckpt_at) >= timedelta(
            seconds=self.lc.checkpoint_interval_s
        )
        if len(self.unflushed) >= self.lc.checkpoint_every or due_time:
            self.checkpoint_now(now)

    def checkpoint_now(self, now: datetime | None = None) -> ChallengerCheckpoint | None:
        with self._lock:
            if self.challenger is None or not self.unflushed:
                return None
            now = now or self.clock()
            self.checkpoint = self.store.save(
                self.challenger,
                app_id=self.app_id,
                watermarks=self.watermarks,
                learned=self.unflushed,
                now=now,
            )
            self.unflushed = []
            self._last_ckpt_at = now
            return self.checkpoint

    def _maybe_purge(self, now: datetime) -> None:
        if self._last_purge is not None and now - self._last_purge < timedelta(hours=1):
            return
        self._last_purge = now
        keep = timedelta(days=self.lc.retention_days)
        self.repo.purge_shadow(now - keep)
        self.repo.purge_sources(now - keep, now)

    # ------------------------------------------------------------- status
    def snapshot(self) -> dict[str, object]:
        with self._lock:
            ch = self.challenger
            return {
                "enabled": self.lc.enabled,
                "mode": "shadow (no influence on enforcement; promotion only via gate + admin)",
                "champion_model": self.champion.record.version if self.champion else None,
                "challenger": None if ch is None else {**ch.state(), "warm": ch.warm},
                "last_checkpoint": None
                if self.checkpoint is None
                else {
                    "id": self.checkpoint.checkpoint_id,
                    "seq": self.checkpoint.seq,
                    "n_learned": self.checkpoint.n_learned,
                    "created_at": self.checkpoint.created_at.isoformat(),
                },
                "quarantine": len(self.quarantine),
                "unflushed_learned": len(self.unflushed),
                "counts": dict(self.counts),
                "excluded": dict(self.excluded),
            }


def checkpoint_root(data_dir: Path) -> Path:
    return data_dir / "challengers"
