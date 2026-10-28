"""M4 adaptation experiments on recorded lab traffic (run on CTRL01, temp state only).

A. Legitimate drift: the shadow learner replays a recorded benign run (as
   CURATED) under the deployed default config and under a labelled relaxed
   experiment config; the challenger is then calibrated and compared with the
   frozen champion on a later, disjoint holdout run of the same population.
   Uncertainty: 95 % bootstrap CIs over *sources* (the independent unit), never
   over overlapping windows.
B. Poisoning: feature-space windows (synthetic, labelled as such; no traffic is
   sent anywhere) that shift non-sensitive behaviour while staying inside the
   sensitive ranges are injected with CURATED provenance (worst case: the
   adversary owns an authenticated path) from 2 sources (concentrated) and from 4
   sources (distributed). Reports how many were learned and how far the
   challenger moved toward the poison.
C. Injected regression: a deliberately mis-calibrated model is promoted inside a
   temporary registry (gate bypassed for this experiment only, recorded in the
   report) and fed the real holdout's verdicts; probation must roll it back.
"""

from __future__ import annotations

import random
import tempfile
from collections.abc import Sequence
from datetime import timedelta
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

import numpy as np

from afw.config import LabConfig
from afw.domain.adaptation import GateCheck
from afw.domain.common import new_id
from afw.domain.detection import DetectionResult, DetectorKind, ModelStatus
from afw.domain.events import HttpObservation
from afw.domain.features import FeatureVector
from afw.domain.learning import ChallengerEvaluation, ProbationStatus
from afw.domain.profiles import BehaviorProfile
from afw.features.extract import EndpointCatalog
from afw.features.windows import replay_windows
from afw.ml.challenger_gate import Holdout, evaluate_challenger, matched_sensitivity, tumbling
from afw.ml.inference import LoadedModel
from afw.ml.online import OnlineChallenger
from afw.ml.online_replay import Stream, learn_stream
from afw.ml.registry import ArtifactStore
from afw.persistence.db import make_engine, upgrade
from afw.persistence.repositories import SqlLearningRepository, SqlModelRepository
from afw.profiling.eligibility import SENSITIVE

RELAXED = {"max_windows_per_source_per_hour": 10_000, "min_source_tenure_s": 0}


def _rows(ws: Sequence[FeatureVector]) -> np.ndarray:
    return np.array([w.as_row() for w in ws], dtype=float)


def _flags(det: Any, ws: Sequence[FeatureVector], thr: float) -> np.ndarray:
    return np.asarray(det.score(_rows(ws))) >= thr if ws else np.array([], dtype=bool)


def source_ci(
    ws: Sequence[FeatureVector], flags: np.ndarray, seed: int = 0, n_boot: int = 2000
) -> dict[str, Any]:
    """Pooled rate plus a 95 % percentile bootstrap CI resampling sources."""
    per: dict[IPv4Address, list[bool]] = {}
    for w, f in zip(ws, flags, strict=True):
        per.setdefault(w.source_ip, []).append(bool(f))
    srcs = sorted(per, key=int)
    if not srcs:
        return {"rate": None, "ci95": None, "n_sources": 0, "n_windows": 0}
    rng = np.random.default_rng(seed)
    boots = []
    for _ in range(n_boot):
        pick = rng.integers(0, len(srcs), len(srcs))
        num = sum(sum(per[srcs[i]]) for i in pick)
        den = sum(len(per[srcs[i]]) for i in pick)
        boots.append(num / den)
    return {
        "rate": round(float(np.mean(flags)), 4),
        "ci95": [
            round(float(np.quantile(boots, 0.025)), 4),
            round(float(np.quantile(boots, 0.975)), 4),
        ],
        "n_sources": len(srcs),
        "n_windows": len(ws),
        "per_source": {str(s): round(float(np.mean(per[s])), 4) for s in srcs},
    }


POISON_KINDS = ("in_distribution", "detectable")


def poison_windows(
    template: Sequence[FeatureVector],
    profile: BehaviorProfile,
    sources: Sequence[str],
    seed: int,
    kind: str = "in_distribution",
) -> list[FeatureVector]:
    """Synthetic feature-space poison (labelled), sensitive features kept at the benign
    median so the sensitive-range rule alone cannot catch it. ``in_distribution``:
    automation-like volume/route pattern the champion happened to score normal;
    ``detectable``: scanner-like unknown routes and novel methods the champion flags.
    Timed like the template run, one window per 30 s per source."""
    rng = random.Random(seed)
    base = {n: float(np.median([w.values[n] for w in template])) for n in template[0].values}
    shift = (
        {
            "req_rate": base["req_rate"] * 6,
            "route_count": 1.0,
            "route_entropy": 0.0,
            "interarrival_cv": 0.05,
        }
        if kind == "in_distribution"
        else {
            "req_rate": base["req_rate"] * 3,
            "route_count": base["route_count"] * 3,
            "route_entropy": base["route_entropy"] + 1.5,
            "unknown_route_frac": 0.6,
            "novel_method_frac": 0.3,
        }
    )
    for name in SENSITIVE:
        shift[name] = min(base[name], profile.features[name].median)
    start, end = template[0].window_start, template[-1].window_end
    out: list[FeatureVector] = []
    t = start + timedelta(seconds=30)
    i = 0
    while t <= end:
        for s in sources:
            vals = {k: max(0.0, v * rng.uniform(0.95, 1.05)) for k, v in {**base, **shift}.items()}
            for k in (
                "unknown_route_frac",
                "novel_method_frac",
                "write_frac",
                "client_err_frac",
                "server_err_frac",
                "auth_fail_frac",
            ):
                vals[k] = min(vals[k], 1.0)
            out.append(
                FeatureVector(
                    app_id=template[0].app_id,
                    source_ip=IPv4Address(s),
                    window_start=t - timedelta(seconds=30),
                    window_end=t,
                    n_requests=max(1, int(vals["req_rate"] * 30)),
                    values=vals,
                    evidence={"untrusted_obs": 0.0, "unjoined_obs": 0.0},
                    request_ids=tuple(f"poison-{s}-{i}-{j}" for j in range(3)),
                    app_versions=template[0].app_versions,
                )
            )
            i += 1
        t += timedelta(seconds=30)
    return out


def _challenger(st: Stream) -> OnlineChallenger:
    if st.learner.challenger is None:
        raise ValueError("no challenger bound")
    return st.learner.challenger


def _stream_report(st: Stream) -> dict[str, Any]:
    sl, ch = st.learner, _challenger(st)
    return {
        "windows": len(st.windows),
        "gate": {"counts": dict(sl.counts), "excluded": dict(sl.excluded)},
        "n_learned": ch.n_learned,
        "window_size": int(ch.detector.window_size),
        "pivots": ch.n_learned // int(ch.detector.window_size),
        "state_changed": ch.blob() != st.before_blob,
        "ms_per_window": round(1000 * st.elapsed_s / max(1, len(st.windows)), 3),
    }


def run_adaptation(
    *,
    cfg: LabConfig,
    profile: BehaviorProfile,
    models: list[LoadedModel],
    catalog: EndpointCatalog,
    learn: Sequence[HttpObservation],
    hold: Sequence[HttpObservation],
    learn_ids: Sequence[str],
    hold_ids: Sequence[str],
    seed: int = 0,
) -> dict[str, Any]:
    relaxed = cfg.learning.model_copy(update=RELAXED)
    hold_windows = tumbling(list(replay_windows(hold, cfg.window, catalog)))
    report: dict[str, Any] = {
        "datasets": {"learn": list(learn_ids), "holdout": list(hold_ids)},
        "provenance_assertion": "recorded benign runs replayed as CURATED (operator-curated)",
        "experiment_config": {
            "relaxed_overrides": RELAXED,
            "reason": "default caps cannot reach a reference pivot within one 45-min run",
        },
    }

    # ---------------------------------------------------------- frozen ensemble
    frozen = {}
    for m in models:
        frozen[m.record.detector.value] = source_ci(
            hold_windows, _flags(m.detector, hold_windows, m.record.threshold), seed
        )
    report["holdout_frozen_detectors"] = frozen

    # ---------------------------------------------------------- A: drift
    a: dict[str, Any] = {}
    streams = {}
    for name, lc in (("default", cfg.learning), ("experiment_relaxed", relaxed)):
        st = learn_stream(
            cfg=cfg,
            profile=profile,
            models=models,
            catalog=catalog,
            learn=learn,
            learning=lc,
            work_dir=Path(tempfile.mkdtemp()),
        )
        streams[name] = st
        a[name] = _stream_report(st)
    st = streams["experiment_relaxed"]
    hst, ch = st.champion, _challenger(st)
    spans = tuple(
        (
            w.source_ip,
            min(x.window_start for x in hold_windows),
            max(x.window_end for x in hold_windows),
        )
        for w in {w.source_ip: w for w in hold_windows}.values()
    )
    holdout = Holdout(
        benign=hold_windows,
        attack=[],
        benign_dataset_ids=tuple(hold_ids),
        attack_dataset_ids=(),
        synthetic_attack=False,
        spans=spans,
    )
    lineage = st.learner.repo.lineage(hst.record.app_id, hst.record.model_id, ch.n_learned)
    gate = evaluate_challenger(
        champion=hst,
        challenger=ch,
        profile=profile,
        holdout=holdout,
        lineage=lineage,
        tainted=set(),
        pc=cfg.promotion,
    )
    a["gate_checks"] = [c.model_dump(mode="json") for c in gate.checks]
    a["gate_passed"] = all(c.passed for c in gate.checks)
    a["gate_metrics"] = gate.metrics
    half = len(hold_windows) // 2
    test = hold_windows[half:]
    a["holdout_test_half"] = {
        "champion_hst_at_champion_threshold": source_ci(
            test, _flags(hst.detector, test, hst.record.threshold), seed
        ),
        "challenger_at_champion_threshold": source_ci(
            test, _flags(ch.detector, test, hst.record.threshold), seed
        ),
        "challenger_at_calibrated_threshold": source_ci(
            test, _flags(ch.detector, test, gate.threshold), seed
        ),
        "calibrated_threshold": round(gate.threshold, 6),
        "champion_threshold": round(hst.record.threshold, 6),
    }
    # Diagnostic only (not a gate input): separates what the learned model state does to
    # sensitivity from what recalibrating its threshold does, on the same matched bases.
    tt = tumbling(test)
    decomposition: dict[str, Any] = {}
    for name, thr in (("champion", hst.record.threshold), ("calibrated", gate.threshold)):
        sens = matched_sensitivity(
            hst.detector, hst.record.threshold, ch.detector, thr, tt, profile
        )
        decomposition[f"challenger_at_{name}_threshold"] = {
            "matched_bases": sens["matched_bases"],
            "per_feature": {
                f: {k: round(v, 4) for k, v in r.items()} for f, r in sens["per_feature"].items()
            },
        }
    a["sensitivity_decomposition"] = decomposition
    report["A_legitimate_drift"] = a

    # ---------------------------------------------------------- B: poisoning
    learn_windows = [w for w in st.windows]
    b: dict[str, Any] = {"note": "synthetic feature-space poison windows (no traffic sent)"}
    sets = {
        "concentrated_2_sources": ["10.77.20.91", "10.77.20.92"],
        "distributed_4_sources": ["10.77.20.91", "10.77.20.92", "10.77.20.93", "10.77.20.94"],
    }
    for kind in POISON_KINDS:
        for label, srcs in sets.items():
            poison = poison_windows(learn_windows, profile, srcs, seed, kind)
            fresh = poison_windows(learn_windows, profile, srcs, seed + 1, kind)[-60:]
            ps = learn_stream(
                cfg=cfg,
                profile=profile,
                models=models,
                catalog=catalog,
                learn=learn,
                learning=relaxed,
                work_dir=Path(tempfile.mkdtemp()),
                inject=poison,
            )
            pch = _challenger(ps)
            learned = ps.learner.repo.lineage(hst.record.app_id, hst.record.model_id, pch.n_learned)
            n_poison = sum(1 for w in learned if str(w.source_ip) in srcs)
            b[f"{kind}/{label}"] = {
                **_stream_report(ps),
                "poison_windows_offered": len(poison),
                "poison_windows_learned": n_poison,
                "poison_share_of_learned": round(n_poison / max(1, len(learned)), 4),
                "fresh_poison_flagged_by_champion": round(
                    float(np.mean(_flags(hst.detector, fresh, hst.record.threshold))), 4
                ),
                "fresh_poison_flagged_by_challenger": round(
                    float(np.mean(_flags(pch.detector, fresh, hst.record.threshold))), 4
                ),
                "fresh_poison_flagged_by_clean_challenger": round(
                    float(np.mean(_flags(ch.detector, fresh, hst.record.threshold))), 4
                ),
            }
    report["B_poisoning"] = b

    # ---------------------------------------------------------- C: regression
    report["C_injected_regression"] = _regression(cfg, hst, hold_windows, models)
    return report


def _regression(
    cfg: LabConfig, hst: LoadedModel, hold: Sequence[FeatureVector], models: list[LoadedModel]
) -> dict[str, Any]:
    from afw.services.challenger import ChallengerLifecycle  # service layer

    work = Path(tempfile.mkdtemp(prefix="afw-m4c-"))
    url = f"sqlite:///{work / 'c.sqlite3'}"
    upgrade(url)
    engine = make_engine(url)
    reg, repo, arts = SqlModelRepository(engine), SqlLearningRepository(engine), ArtifactStore(work)
    path, sha, _ = arts.save(hst.record.app_id, hst.record.model_id, hst.detector)
    parent = hst.record.model_copy(
        update={"artifact_path": path, "artifact_sha256": sha, "status": ModelStatus.ACTIVE}
    )
    reg.save(parent)
    scores = np.asarray(hst.detector.score(_rows(hold)))
    bad_thr = float(np.quantile(scores, 0.5))  # injected regression: alarms on half of benign
    cid = new_id("mdl")
    cpath, csha, _ = arts.save(hst.record.app_id, cid, hst.detector)
    reg.save(
        parent.model_copy(
            update={
                "model_id": cid,
                "version": parent.version + "-regressed",
                "threshold": bad_thr,
                "artifact_path": cpath,
                "artifact_sha256": csha,
                "status": ModelStatus.CANDIDATE,
            }
        )
    )
    clock = [hold[0].window_end]
    ev = ChallengerEvaluation(
        evaluation_id=new_id("ceval"),
        app_id=parent.app_id,
        evaluated_at=clock[0],
        checkpoint_id="injected",
        candidate_model_id=cid,
        parent_model_id=parent.model_id,
        n_learned=0,
        threshold=bad_thr,
        benign_dataset_ids=(),
        attack_dataset_ids=(),
        checks=(
            GateCheck(
                name="injected_for_rollback_experiment",
                passed=True,
                detail="gate bypassed in a temporary registry for experiment C only",
            ),
        ),
        metrics={"challenger_fpr": cfg.promotion.target_fpr},
    )
    repo.add_evaluation(ev)

    class _Audit:
        def __init__(self) -> None:
            self.events: list[str] = []

        def record(self, actor: str, action: str, subject: str, detail: Any = None) -> None:
            self.events.append(action)

        def recent(self, limit: int = 100) -> list[dict[str, object]]:
            return []

    audit = _Audit()
    unused: Any = None  # evaluate() is not exercised here: no learning service/store
    lc = ChallengerLifecycle(
        cfg,
        unused,
        repo,
        unused,
        reg,
        arts,
        unused,
        audit,
        false_positives=lambda a, s: 0,
        clock=lambda: clock[0],
    )
    lc.promote(parent.app_id, ev.evaluation_id, "experiment", "M4-C injected regression")
    rolled_at = None
    for i, w in enumerate(hold):
        clock[0] = w.window_end
        score = float(scores[i])
        lc.observe(
            parent.app_id,
            [
                DetectionResult(
                    detection_id="x",
                    detector=DetectorKind.HALF_SPACE_TREES,
                    model_version="regressed",
                    profile_version=parent.profile_version,
                    app_id=parent.app_id,
                    source_ip=w.source_ip,
                    window_end=w.window_end,
                    n_requests=w.n_requests,
                    score=score,
                    threshold=bad_thr,
                    is_anomalous=score >= bad_thr,
                    benign_percentile=50,
                )
            ],
        )
        if lc.check(parent.app_id, w.window_end):
            rolled_at = i + 1
            break
    active = reg.active(parent.app_id, DetectorKind.HALF_SPACE_TREES.value)
    p = repo.probations(parent.app_id)[0]
    regressed = reg.get(cid)
    return {
        "note": "regressed model = champion HST with threshold at the benign holdout median; "
        "verdicts are the real holdout windows in event-time order",
        "rolled_back": p.status is ProbationStatus.ROLLED_BACK,
        "windows_until_rollback": rolled_at,
        "event_time_to_rollback_s": None
        if rolled_at is None
        else (hold[rolled_at - 1].window_end - hold[0].window_end).total_seconds(),
        "reason": p.reason,
        "active_after": [m.version for m in active],
        "regressed_status_after": None if regressed is None else regressed.status.value,
        "audit": audit.events,
    }
