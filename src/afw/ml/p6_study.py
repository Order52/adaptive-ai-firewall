"""P6 study: candidate models compared on benign generalization and sensitivity.

Protocol: ``docs/engineering/P6_GENERALIZATION_AND_SENSITIVITY.md``. Candidates are
trained with the production recipe (``build_profile`` + ``train_and_register``, target
FPR on calibration windows) and evaluated with the production windowing, correlation
and decision logic (``run_experiment`` with a candidate scorer). Nothing is written to
the controller: artifacts go to a caller-supplied scratch store.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

import numpy as np

from afw.domain.detection import DetectionResult, DetectorKind
from afw.domain.features import FeatureVector
from afw.domain.profiles import BehaviorProfile
from afw.features.extract import EndpointCatalog, compute_features
from afw.ml import regression_suite as rs
from afw.ml.adaptation_experiment import source_ci
from afw.ml.challenger_gate import tumbling
from afw.ml.evaluation import threshold_for_fpr
from afw.ml.experiments import run_experiment
from afw.ml.inference import InferenceEngine, LoadedModel, Strategy, _independent_of
from afw.ml.registry import ArtifactStore
from afw.ml.security_path import SecurityPath, evidence_weighted
from afw.ml.training import TrainingData, train_and_register
from afw.profiling.builder import build_profile

ENFORCING = (DetectorKind.ROBUST_STATS, DetectorKind.ISOLATION_FOREST)
KINDS = (DetectorKind.ROBUST_STATS, DetectorKind.ISOLATION_FOREST, DetectorKind.HALF_SPACE_TREES)
Transform = Callable[[FeatureVector], FeatureVector]


def _identity(fv: FeatureVector) -> FeatureVector:
    return fv


def cohort(fv: FeatureVector) -> bool:
    """Candidate C's cohorts: windows with login attempts vs without."""
    return fv.evidence.get("login_attempts", 0.0) > 0


@dataclass
class Candidate:
    name: str
    profile: BehaviorProfile
    models: list[LoadedModel]
    catalog: EndpointCatalog
    transform: Transform = _identity
    cohort_thresholds: dict[DetectorKind, dict[bool, float]] | None = None
    security: SecurityPath | None = None
    notes: dict[str, Any] = field(default_factory=dict)
    val_raw: list[FeatureVector] = field(default_factory=list)  # calibration windows

    def model(self, kind: DetectorKind) -> LoadedModel:
        return next(m for m in self.models if m.record.detector is kind)

    def _thresholds(self, kind: DetectorKind, ws: Sequence[FeatureVector]) -> np.ndarray:
        if self.cohort_thresholds is None:
            return np.full(len(ws), self.model(kind).record.threshold)
        t = self.cohort_thresholds[kind]
        return np.array([t[cohort(w)] for w in ws])

    def flags(self, windows: Sequence[FeatureVector]) -> dict[str, np.ndarray]:
        """Per-detector flags for windows built with this candidate's catalog."""
        tw = [self.transform(w) for w in windows]
        x = np.array([w.as_row() for w in tw], dtype=float)
        out: dict[str, np.ndarray] = {}
        for kind in KINDS:
            if not len(x):
                out[kind.value] = np.array([], dtype=bool)
                continue
            s = np.asarray(self.model(kind).detector.score(x))
            out[kind.value] = s >= self._thresholds(kind, tw)
        ml = out[ENFORCING[0].value] | out[ENFORCING[1].value]
        out["ml"] = ml
        enforcing = ml
        if self.security is not None:
            empty = np.array([], dtype=bool)
            sec = self.security.flags(windows) if windows else empty
            out["security"] = sec
            # decomposition (P6 reporting): what the fixed ceilings alone catch, and
            # what each side adds over the other, so the security path cannot hide
            # weak ML and vice versa
            out["security_ceiling"] = self.security.ceiling_flags(windows) if windows else empty
            out["ml_not_security"] = ml & ~sec
            out["security_not_ml"] = sec & ~ml
            enforcing = ml | sec
        out["enforcing"] = enforcing
        return out

    def scorer(self) -> Callable[[FeatureVector, Strategy], list[DetectionResult]]:
        """Detections as the controller would produce them for this candidate (the
        security path is not part of the current decision pipeline; its decision
        effect is reported separately as an upper bound)."""
        engine = InferenceEngine()
        engine.load(self.profile, self.models)

        def score(fv: FeatureVector, strategy: Strategy) -> list[DetectionResult]:
            engine.strategy = strategy
            tfv = self.transform(fv)
            dets = engine.score(tfv)
            if self.cohort_thresholds is None:
                return dets
            out = []
            row = np.array(tfv.as_row(), dtype=float)
            for d in dets:
                thr = self.cohort_thresholds[d.detector][cohort(tfv)]
                anomalous = d.score >= thr
                det = self.model(d.detector).detector
                out.append(
                    d.model_copy(
                        update={
                            "threshold": round(thr, 5),
                            "is_anomalous": anomalous,
                            "independent_of": (
                                _independent_of(det, row, thr, tfv) if anomalous else ()
                            ),
                        }
                    )
                )
            return out

        return score


# ------------------------------------------------------------------ training
def train(
    name: str,
    learning: Any,
    app_id: str,
    train_ids: Sequence[str],
    val_ids: Sequence[str],
    store: ArtifactStore,
    *,
    weighted: bool = False,
    cohorts: bool = False,
    security: bool = False,
    target_fpr: float = 0.01,
    seed: int = 42,
    created_at: datetime,
) -> Candidate:
    """The bootstrap recipe of ``LearningService.bootstrap`` without registering."""
    transform: Transform = evidence_weighted if weighted else _identity
    obs = learning._benign_observations(train_ids)
    catalog = learning._catalog_from(app_id, obs, min_sources=2)
    train_vectors = [transform(v) for v in learning.windows(obs, catalog)]
    profile = build_profile(
        app_id=app_id,
        version=900,
        parent_version=None,
        window=learning.cfg.window,
        vectors=train_vectors,
        observations=obs,
        dataset_ids=train_ids,
        created_at=created_at,
    )
    cat = learning.catalog(app_id, profile)
    val_raw, _ = learning._labeled(val_ids, cat)
    val = [transform(v) for v in val_raw]
    records = train_and_register(
        profile=profile,
        data=TrainingData(
            train_benign=train_vectors,
            val_benign=val,
            val_attack=[],
            train_dataset_ids=tuple(train_ids),
            val_dataset_ids=tuple(val_ids),
        ),
        store=store,
        kinds=KINDS,
        target_fpr=target_fpr,
        created_at=created_at,
        seed=seed,
    )
    models = [LoadedModel(record=r, detector=store.load(r)) for r in records]
    cand = Candidate(name, profile, models, cat, transform, val_raw=list(val_raw))
    if cohorts:
        x = np.array([v.as_row() for v in val], dtype=float)
        mask = np.array([cohort(v) for v in val])
        cand.cohort_thresholds = {}
        for m in models:
            s = np.asarray(m.detector.score(x))
            cand.cohort_thresholds[m.record.detector] = {
                c: threshold_for_fpr(s[mask == c], target_fpr) for c in (False, True)
            }
        cand.notes["cohort_windows"] = {"login": int(mask.sum()), "no_login": int((~mask).sum())}
    if security:
        cand.security = SecurityPath(alpha=target_fpr)
        cand.security.calibrate(val_raw)
        cand.notes["security_effective"] = cand.security.effective()
    cand.notes |= {
        "train": list(train_ids),
        "val": list(val_ids),
        "train_windows": len(train_vectors),
        "val_windows": len(val),
        "thresholds": {m.record.detector.value: round(m.record.threshold, 5) for m in models},
    }
    return cand


# ---------------------------------------------------------------- evaluation
_PERSONA = re.compile(r"^persona (\S+): .*'archetype': '([a-z]+)'")


def archetypes(log_paths: Sequence[Path]) -> dict[IPv4Address, str]:
    """Source -> archetype from generator logs (v1 persona lines map to 'v1')."""
    out: dict[IPv4Address, str] = {}
    for p in log_paths:
        for line in p.read_text().splitlines():
            if not line.startswith("persona "):
                continue
            m = _PERSONA.match(line)
            ip = IPv4Address(line.split()[1].rstrip(":"))
            out[ip] = m.group(2) if m else "v1"
    return out


def benign_eval(
    cand: Candidate,
    learning: Any,
    cfg: Any,
    manifest: Any,
    observations: Sequence[Any],
    arche: dict[IPv4Address, str],
    seed: int = 0,
) -> dict[str, Any]:
    windows = learning.windows(observations, cand.catalog)
    tw = tumbling(windows)
    flags = cand.flags(tw)
    det: dict[str, Any] = {}
    for name, f in flags.items():
        r = source_ci(tw, f, seed)
        per = r.pop("per_source", {})
        n_req = sum(w.n_requests for w in tw)
        r["users_with_flag"] = sum(1 for v in per.values() if v > 0)
        r["requests_in_flagged"] = sum(w.n_requests for w, x in zip(tw, f, strict=True) if x)
        r["requests"] = n_req
        by_arch: dict[str, list[int]] = {}
        for w, x in zip(tw, f, strict=True):
            a = arche.get(w.source_ip, "unknown")
            by_arch.setdefault(a, [0, 0])
            by_arch[a][0] += int(x)
            by_arch[a][1] += 1
        r["by_archetype"] = {a: {"flagged": v[0], "windows": v[1]} for a, v in by_arch.items()}
        det[name] = r
    rep = run_experiment(
        cfg=cfg,
        profile=cand.profile,
        models=cand.models,
        manifest=manifest,
        observations=observations,
        scorer=cand.scorer(),
    )
    m2 = next(a for a in rep.arms if a.strategy == Strategy.ML.value)
    m1 = next(a for a in rep.arms if a.strategy == Strategy.STATISTICAL.value)
    out: dict[str, Any] = {
        "dataset": manifest.dataset_id,
        "tumbling_windows": len(tw),
        "users": len({w.source_ip for w in tw}),
        "detectors": det,
        "decision": {
            arm.arm: {
                "users_restricted": arm.benign_sources_flagged,
                "users": arm.benign_sources,
                "requests_impacted": arm.benign_requests_impacted,
                "requests": arm.benign_requests,
                "legit_request_success": arm.legit_request_success,
            }
            for arm in (m1, m2)
        },
    }
    if cand.security is not None:
        restricted = {IPv4Address(ip) for ip in m2.benign_sources_flagged_ips}
        sec = {w.source_ip for w, x in zip(tw, flags["security"], strict=True) if x}
        out["decision"]["M2+security_upper_bound"] = {
            "users_restricted": len(restricted | sec),
            "security_flagged_users": sorted(str(s) for s in sec),
        }
    return out


def sensitivity(
    cands: Sequence[Candidate], bases: Sequence[rs.Base], window: Any
) -> dict[str, Any]:
    """Flag rate of each candidate on every family and intensity, on the same bases.
    ``conditional`` counts only bases the candidate scores normal unmodified."""
    out: dict[str, Any] = {"bases": len(bases), "candidates": {}}
    for c in cands:
        base_w = [
            compute_features(list(b.observations), window, c.catalog, b.start, b.end) for b in bases
        ]
        normal = ~c.flags(base_w)["enforcing"]
        res: dict[str, Any] = {"bases_normal": int(normal.sum())}
        for fam, ks in rs.FAMILIES.items():
            for k in ks:
                ws = [rs.case_window(fam, k, b, window, c.catalog) for b in bases]
                f = c.flags(ws)
                res[f"{fam}@{k}"] = {
                    name: {
                        "rate": round(float(v.mean()), 4),
                        "conditional": (
                            round(float(v[normal].mean()), 4) if normal.any() else None
                        ),
                    }
                    for name, v in f.items()
                }
        out["candidates"][c.name] = res
    return out


def must_detect_min(sens: dict[str, Any], name: str) -> float:
    res = sens["candidates"][name]
    return float(min(res[f"{fam}@{k}"]["enforcing"]["rate"] for fam, k in rs.MUST_DETECT.items()))


# ------------------------------------------------------- adaptation stress (A1)
STRESS_CASES = (("brute_force", 5), ("stuffing", 5), ("enumeration", 10), ("idor", 10))


def stress_windows(
    cand: Candidate, stress_bases: Sequence[rs.Base], n: int, window: Any
) -> list[FeatureVector]:
    """``n`` sub-must attack-shaped windows, families in equal shares, cycling bases."""
    out = []
    for i in range(n):
        fam, k = STRESS_CASES[i % len(STRESS_CASES)]
        out.append(
            rs.case_window(
                fam,
                k,
                stress_bases[(i // len(STRESS_CASES)) % len(stress_bases)],
                window,
                cand.catalog,
            )
        )
    return out


def stressed(
    cand: Candidate,
    stress_bases: Sequence[rs.Base],
    window: Any,
    share: float = 0.03,
    target_fpr: float = 0.01,
) -> Candidate:
    """The candidate with its adaptable thresholds recalibrated on calibration windows
    plus ``share`` contaminating sub-must windows (P6 amendment A1). Profiles, fitted
    models and the security path's ceilings are unchanged."""
    if not cand.val_raw:
        raise ValueError(f"{cand.name}: no calibration windows")
    n = int(np.ceil(share * len(cand.val_raw)))
    cal_raw = [*cand.val_raw, *stress_windows(cand, stress_bases, n, window)]
    cal = [cand.transform(w) for w in cal_raw]
    x = np.array([w.as_row() for w in cal], dtype=float)
    models = []
    for m in cand.models:
        thr = threshold_for_fpr(np.asarray(m.detector.score(x)), target_fpr)
        models.append(
            LoadedModel(record=m.record.model_copy(update={"threshold": thr}), detector=m.detector)
        )
    out = Candidate(
        f"{cand.name}~stress",
        cand.profile,
        models,
        cand.catalog,
        cand.transform,
        notes={"stress_windows": n, "calibration_windows": len(cand.val_raw)},
        val_raw=cal_raw,
    )
    if cand.cohort_thresholds is not None:
        mask = np.array([cohort(w) for w in cal])
        out.cohort_thresholds = {
            m.record.detector: {
                c: threshold_for_fpr(np.asarray(m.detector.score(x[mask == c])), target_fpr)
                for c in (False, True)
            }
            for m in cand.models
        }
    if cand.security is not None:
        out.security = SecurityPath(alpha=target_fpr)
        out.security.calibrate(cal_raw)
        out.notes["security_effective"] = out.security.effective()
    out.notes["thresholds"] = {
        m.record.detector.value: round(m.record.threshold, 5) for m in models
    }
    return out
