"""P1: frozen-model false-positive evaluation on held-out benign runs.

Every rate is reported with its denominator, at three units, because a single pooled
window rate over-counts overlapping windows and hides how many *people* are affected:

* window: non-overlapping (tumbling) windows only, with a 95 % bootstrap CI that
  resamples sources (windows of one user are not independent);
* user: share of benign sources with at least one flagged window, and the per-user
  rate distribution;
* request: share of benign requests that fall inside a flagged tumbling window (each
  request belongs to exactly one tumbling window, so it is counted once).

Decision-level impact (what the controller would actually propose, after evidence
correlation and the safety policy) comes from the existing M0/M1/M2 replay.

Models are evaluated as frozen artefacts at their stored thresholds: nothing here
fits, recalibrates or selects anything on the evaluated data.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import numpy as np

from afw.config import LabConfig
from afw.domain.events import HttpObservation
from afw.domain.features import FeatureVector
from afw.domain.profiles import BehaviorProfile
from afw.ml.adaptation_experiment import source_ci
from afw.ml.challenger_gate import tumbling
from afw.ml.datasets import DatasetManifest, Role
from afw.ml.experiments import run_experiment
from afw.ml.inference import LoadedModel


def detector_rates(
    windows: Sequence[FeatureVector], model: LoadedModel, seed: int = 0
) -> dict[str, Any]:
    tw = tumbling(windows)
    flags = (
        np.asarray(model.detector.score(np.array([w.as_row() for w in tw], dtype=float)))
        >= model.record.threshold
        if tw
        else np.array([], dtype=bool)
    )
    out = source_ci(tw, flags, seed)
    per_user = list(out.get("per_source", {}).values())
    n_req = sum(w.n_requests for w in tw)
    flagged_req = sum(w.n_requests for w, f in zip(tw, flags, strict=True) if f)
    out["users"] = {
        "n": len(per_user),
        "with_any_flag": sum(1 for r in per_user if r > 0),
        "median_rate": round(float(np.median(per_user)), 4) if per_user else None,
        "max_rate": round(float(np.max(per_user)), 4) if per_user else None,
    }
    out["requests"] = {
        "n": n_req,
        "in_flagged_windows": flagged_req,
        "rate": round(flagged_req / n_req, 4) if n_req else None,
    }
    return out


def evaluate_benign(
    *,
    cfg: LabConfig,
    profile: BehaviorProfile,
    models: Sequence[LoadedModel],
    manifest: DatasetManifest,
    observations: Sequence[HttpObservation],
    windows: Sequence[FeatureVector],
    seed: int = 0,
) -> dict[str, Any]:
    """Detector- and decision-level FP of one frozen profile on one benign dataset."""
    if any(s.role is not Role.BENIGN for s in manifest.sources):
        raise ValueError(f"{manifest.dataset_id}: only all-benign datasets are evaluated here")
    report = run_experiment(
        cfg=cfg, profile=profile, models=models, manifest=manifest, observations=observations
    )
    return {
        "dataset": manifest.dataset_id,
        "purpose": manifest.purpose.value,
        "start": manifest.start.isoformat(),
        "end": manifest.end.isoformat(),
        "profile_version": profile.version,
        "profile_datasets": list(profile.provenance.dataset_ids),
        "observations": len(observations),
        "detectors": {
            m.record.detector.value: {
                "model_id": m.record.model_id,
                "threshold": round(m.record.threshold, 6),
                **detector_rates(windows, m, seed),
            }
            for m in models
        },
        "decisions": {
            a.arm: {
                "strategy": a.strategy,
                "benign_windows": a.n_benign_windows,
                "fp_windows": a.fp,
                "fpr": a.fpr,
                "benign_sources": a.benign_sources,
                "benign_sources_restricted": a.benign_sources_flagged,
                "benign_requests": a.benign_requests,
                "benign_requests_impacted": a.benign_requests_impacted,
                "legit_request_success": a.legit_request_success,
                "decisions": a.decisions,
            }
            for a in report.arms
        },
    }
