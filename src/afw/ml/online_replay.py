"""Offline replay of recorded traffic through the *live* online-learning path.

Recorded observations are windowed exactly as live, scored by the trusted
detectors, correlated, passed through the eligibility gate and quarantine, and
learned by a fresh shadow challenger, driven by event time. Used as M2
evidence (learning really happens on real lab traffic) and by M4.

Recorded datasets are replayed with provenance CURATED: the operator asserts
they are the curated runs listed in their manifests. That assertion is part of
the report; it is never applied to live telemetry.
"""

from __future__ import annotations

import resource
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import numpy as np

from afw.config import LabConfig, OnlineLearningConfig
from afw.correlation.engine import CorrelationEngine
from afw.domain.detection import DetectorKind
from afw.domain.events import HttpObservation, Provenance
from afw.domain.features import FeatureVector
from afw.domain.profiles import BehaviorProfile
from afw.features.extract import EndpointCatalog
from afw.features.windows import replay_windows
from afw.ml.inference import InferenceEngine, LoadedModel
from afw.ml.online import CheckpointStore
from afw.persistence.db import make_engine, upgrade
from afw.persistence.repositories import SqlLearningRepository

if TYPE_CHECKING:
    from afw.services.shadow import ShadowLearner


class _Audit:
    def record(self, actor: str, action: str, subject: str, detail: dict[str, object]) -> None:
        return None

    def recent(self, limit: int = 100) -> list[dict[str, object]]:
        return []


def _scores(det: Any, windows: Sequence[FeatureVector]) -> np.ndarray:
    if not windows:
        return np.array([])
    return np.asarray(det.score(np.array([w.as_row() for w in windows], dtype=float)))


@dataclass
class Stream:
    """A shadow learner driven through recorded windows by event time."""

    learner: ShadowLearner
    champion: LoadedModel
    windows: list[FeatureVector]
    before_blob: bytes
    before_state: dict[str, float | int]
    elapsed_s: float
    end: datetime
    new_learner: Callable[[], ShadowLearner]


def learn_stream(
    *,
    cfg: LabConfig,
    profile: BehaviorProfile,
    models: list[LoadedModel],
    catalog: EndpointCatalog,
    learn: Sequence[HttpObservation],
    learning: OnlineLearningConfig | None = None,
    work_dir: Path | None = None,
    inject: Sequence[FeatureVector] = (),
) -> Stream:
    """Window ``learn`` (as CURATED) plus pre-built ``inject`` windows, score them with
    the trusted detectors and correlation, and feed the gate + shadow learner."""
    from afw.services.shadow import ShadowLearner  # service layer; avoid import cycle

    hst = next((m for m in models if m.record.detector is DetectorKind.HALF_SPACE_TREES), None)
    if hst is None:
        raise ValueError("trusted profile has no HST champion")
    lc = learning or cfg.learning
    cfg = cfg.model_copy(update={"learning": lc})
    work = work_dir or Path(tempfile.mkdtemp(prefix="afw-online-replay-"))
    url = f"sqlite:///{work / 'replay.sqlite3'}"
    upgrade(url)
    repo = SqlLearningRepository(make_engine(url))
    store = CheckpointStore(work / "challengers", repo, keep=lc.keep_checkpoints)
    now_ref: list[Any] = [None]

    def new_learner() -> ShadowLearner:
        sl = ShadowLearner(
            cfg,
            repo,
            store,
            _Audit(),
            policed=lambda ip: False,
            reported=lambda app: set(),
            clock=lambda: now_ref[0],
        )
        sl.reload(profile, hst)
        return sl

    inference = InferenceEngine()
    inference.load(profile, models)
    correlation = CorrelationEngine(cfg.risk)
    for m in models:
        correlation.set_score_span(m.record.detector, m.record.benign_score_quantiles)

    curated = [
        o.model_copy(update={"provenance": Provenance.CURATED})
        for o in sorted(learn, key=lambda o: o.observed_at)
    ]
    windows = sorted(
        [*replay_windows(curated, cfg.window, catalog), *inject], key=lambda w: w.window_end
    )
    if not windows:
        raise ValueError("no learning windows")
    now_ref[0] = windows[0].window_start
    sl = new_learner()
    assert sl.challenger is not None
    before_state, before_blob = sl.challenger.state(), sl.challenger.blob()
    t0 = time.perf_counter()
    for fv in windows:
        now_ref[0] = fv.window_end
        sl.submit(fv, correlation.assess(fv, inference.score(fv), fv.window_end))
        sl.process(fv.window_end)
    end = windows[-1].window_end + timedelta(
        seconds=lc.admission_delay_s + lc.population_window_s + 1
    )
    now_ref[0] = end
    sl.process(end)
    return Stream(
        learner=sl,
        champion=hst,
        windows=windows,
        before_blob=before_blob,
        before_state=before_state,
        elapsed_s=time.perf_counter() - t0,
        end=end,
        new_learner=new_learner,
    )


def replay_online(
    *,
    cfg: LabConfig,
    profile: BehaviorProfile,
    models: list[LoadedModel],
    catalog: EndpointCatalog,
    learn: Sequence[HttpObservation],
    probe: Sequence[HttpObservation],
    learning: OnlineLearningConfig | None = None,
    work_dir: Path | None = None,
) -> dict[str, Any]:
    lc = learning or cfg.learning
    probe_windows = list(replay_windows(probe, cfg.window, catalog))
    st = learn_stream(
        cfg=cfg,
        profile=profile,
        models=models,
        catalog=catalog,
        learn=learn,
        learning=lc,
        work_dir=work_dir,
    )
    sl, hst = st.learner, st.champion
    assert sl.challenger is not None
    champion_probe = _scores(hst.detector, probe_windows)
    # the challenger starts as a deep copy of the champion: identical scores
    challenger_probe_before = champion_probe
    thr = hst.record.threshold
    elapsed = st.elapsed_s
    learn_windows = st.windows
    before_state, before_blob = st.before_state, st.before_blob
    ckpt = sl.checkpoint_now(st.end) or sl.checkpoint  # may already be flushed on interval
    after_state = sl.challenger.state()
    challenger_probe_after = _scores(sl.challenger.detector, probe_windows)

    restarted = st.new_learner()
    restore_exact = (  # None: nothing learned, no checkpoint to restore
        None
        if ckpt is None
        else restarted.challenger is not None
        and restarted.challenger.blob() == sl.challenger.blob()
        and restarted.challenger.n_learned == sl.challenger.n_learned
    )

    def summary(a: np.ndarray) -> dict[str, float] | None:
        if not a.size:
            return None
        return {
            "mean": round(float(a.mean()), 5),
            "p50": round(float(np.median(a)), 5),
            "p95": round(float(np.quantile(a, 0.95)), 5),
            "anomalous_at_champion_threshold": round(float((a >= thr).mean()), 4),
        }

    return {
        "provenance_assertion": "learn set replayed as CURATED (operator-curated recorded runs)",
        "learning_config": lc.model_dump(),
        "champion": {"model": hst.record.version, "threshold": thr},
        "windows": {"learn": len(learn_windows), "probe": len(probe_windows)},
        "gate": {"counts": dict(sl.counts), "excluded": dict(sl.excluded)},
        "state_before": before_state,
        "state_after": after_state,
        "state_changed": sl.challenger.blob() != before_blob,
        "pivots": after_state["n_learned"] // max(1, int(after_state["window_size"])),
        "probe_scores": {
            "champion_frozen": summary(champion_probe),
            "challenger_before": summary(challenger_probe_before),
            "challenger_after": summary(challenger_probe_after),
            "mean_abs_change": round(
                float(np.abs(challenger_probe_after - challenger_probe_before).mean()), 6
            )
            if probe_windows
            else None,
        },
        "checkpoint": None
        if ckpt is None
        else {"seq": ckpt.seq, "sha256": ckpt.sha256, "bytes": ckpt.size_bytes},
        "restart_restores_exact_state": restore_exact,
        "cost": {
            "seconds": round(elapsed, 3),
            "ms_per_window": round(1000 * elapsed / len(learn_windows), 3),
            "max_rss_mb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1),
        },
    }
