"""Streaming-ML and full-hybrid evaluation arms (directive item 6).

* ``S-ML``: robust statistics plus a Half-Space-Trees challenger that learns online
  during the replay, through the live admission gate (``ShadowLearner``: taint,
  quarantine, rate and share caps, corroboration), scored before it learns from a
  window (prequential), at the champion HST threshold.
* ``HYB``: the frozen M2 detectors (robust statistics + Isolation Forest) plus the
  same online HST, all enforcing.

The live gate is deliberately slow (10 min quarantine, 30 min source tenure), so a
fresh learner learns nothing from a 15-30 min run. ``warmup`` observations (earlier
benign recorded runs, in event-time order, all before the evaluated run) are streamed
through the same gate first, as the history a running system would have; the summary
reports what was learned during warm-up and during the run separately.

Both are counterfactual arms for evaluation only. Live, HST stays shadow and is
never enforcing; these arms are not selectable as a controller strategy. Learning
uses the recorded provenance as is (mTLS observations count as trusted, as live);
labels are never visible to the learner.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

from afw.config import LabConfig, OnlineLearningConfig
from afw.correlation.engine import CorrelationEngine
from afw.domain.detection import DetectionResult, DetectorKind
from afw.domain.events import HttpObservation
from afw.domain.features import FeatureVector
from afw.domain.profiles import BehaviorProfile
from afw.domain.risk import RiskAssessment
from afw.features.windows import replay_windows
from afw.ml.experiments import ArmHooks, ExtraArm, Policed, _catalog
from afw.ml.inference import InferenceEngine, LoadedModel
from afw.ml.online_replay import hst_champion, replay_learner

if TYPE_CHECKING:
    from afw.services.shadow import ShadowLearner

STREAMING = (DetectorKind.ROBUST_STATS, DetectorKind.HALF_SPACE_TREES)
HYBRID = (
    DetectorKind.ROBUST_STATS,
    DetectorKind.ISOLATION_FOREST,
    DetectorKind.HALF_SPACE_TREES,
)


class _Engine(InferenceEngine):
    def __init__(self, kinds: Sequence[DetectorKind]) -> None:
        super().__init__()
        self._kinds = list(kinds)

    def active_kinds(self) -> list[DetectorKind]:
        return list(self._kinds)


def _arm(
    name: str,
    label: str,
    kinds: Sequence[DetectorKind],
    cfg: LabConfig,
    profile: BehaviorProfile,
    models: Sequence[LoadedModel],
    learning: OnlineLearningConfig | None,
    work_dir: Path | None,
    warmup: Sequence[HttpObservation],
) -> ExtraArm:
    def build(policed: Policed) -> ArmHooks:
        hst = hst_champion(models)
        lc = (learning or cfg.learning).model_copy(update={"enabled": True})
        now_ref: list[Any] = [None]
        work = None if work_dir is None else work_dir / name
        if work is not None:
            work.mkdir(parents=True, exist_ok=True)
        sl = replay_learner(
            cfg.model_copy(update={"learning": lc}), profile, hst, now_ref, work, policed
        )()
        frozen = [m for m in models if m.record.detector is not DetectorKind.HALF_SPACE_TREES]
        engine = _Engine(kinds)
        warm = _warm_up(sl, now_ref, cfg, profile, models, warmup)
        assert sl.challenger is not None
        learned_before = sl.challenger.n_learned

        def score(fv: FeatureVector) -> list[DetectionResult]:
            assert sl.challenger is not None
            live = LoadedModel(record=hst.record, detector=sl.challenger.detector)
            engine.load(profile, [*frozen, live])
            return engine.score(fv)

        def after(fv: FeatureVector, ra: RiskAssessment) -> None:
            now_ref[0] = fv.window_end
            sl.submit(fv, ra)
            sl.process(fv.window_end)

        def summary() -> dict[str, Any]:
            assert sl.challenger is not None
            return {
                "warmup_windows": warm,
                "learned_in_warmup": learned_before,
                "learned_windows": sl.challenger.n_learned - learned_before,
                "gate": dict(sl.counts),
                "excluded": dict(sl.excluded),
                "threshold": hst.record.threshold,
            }

        return ArmHooks(score, after, summary)

    return ExtraArm(name, label, build)


def _warm_up(
    sl: ShadowLearner,
    now_ref: list[Any],
    cfg: LabConfig,
    profile: BehaviorProfile,
    models: Sequence[LoadedModel],
    warmup: Sequence[HttpObservation],
) -> int:
    """Stream ``warmup`` through the learner as live would: trusted (frozen M2 + HST
    champion) scoring and correlation, then the gate. Returns the window count."""
    if not warmup:
        return 0
    inference = InferenceEngine()
    inference.load(profile, list(models))
    correlation = CorrelationEngine(cfg.risk)
    for m in models:
        correlation.set_score_span(m.record.detector, m.record.benign_score_quantiles)
    catalog = _catalog(cfg, profile)
    n = 0
    for fv in replay_windows(sorted(warmup, key=lambda o: o.observed_at), cfg.window, catalog):
        now_ref[0] = fv.window_end
        sl.submit(fv, correlation.assess(fv, inference.score(fv), fv.window_end))
        sl.process(fv.window_end)
        n += 1
    return n


def streaming_arms(
    cfg: LabConfig,
    profile: BehaviorProfile,
    models: Sequence[LoadedModel],
    learning: OnlineLearningConfig | None = None,
    work_dir: Path | None = None,
    warmup: Sequence[HttpObservation] = (),
) -> list[ExtraArm]:
    """``warmup`` must end before the evaluated run starts (event time only moves on)."""
    args = (cfg, profile, models, learning, work_dir, warmup)
    return [
        _arm("S-ML", "streaming", STREAMING, *args),
        _arm("HYB", "hybrid", HYBRID, *args),
    ]
