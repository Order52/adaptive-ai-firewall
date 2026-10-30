"""Cross-run evaluation of the M0/M1/M2 arms (M6).

Each labelled attack run (one dataset) is replayed by ``run_experiment``; this module
aggregates per arm with the **run** as the independent unit. Means come with 95 %
percentile-bootstrap CIs over runs, and no CI is reported for fewer than
``MIN_RUNS_FOR_CI`` runs. Synthetic datasets are refused unless explicitly allowed,
and then every number is labelled SYNTHETIC.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import numpy as np

from afw.ml.datasets import DatasetManifest
from afw.ml.experiments import ExperimentReport

MIN_RUNS_FOR_CI = 3
METRICS = (
    "recall",
    "fpr",
    "containment",
    "median_detection_latency_s",
    "legit_request_success",
)


def is_synthetic(m: DatasetManifest) -> bool:
    return "synthetic" in f"{m.scenario} {m.generator}".lower()


def _ci(values: Sequence[float], seed: int, n_boot: int = 2000) -> list[float] | None:
    if len(values) < MIN_RUNS_FOR_CI:
        return None
    rng = np.random.default_rng(seed)
    arr = np.asarray(values, dtype=float)
    boots = [float(np.mean(rng.choice(arr, size=len(arr)))) for _ in range(n_boot)]
    return [round(float(np.quantile(boots, 0.025)), 4), round(float(np.quantile(boots, 0.975)), 4)]


def aggregate(
    reports: Sequence[ExperimentReport],
    manifests: Sequence[DatasetManifest],
    *,
    allow_synthetic: bool = False,
    seed: int = 0,
) -> dict[str, Any]:
    synthetic = [m.dataset_id for m in manifests if is_synthetic(m)]
    if synthetic and not allow_synthetic:
        raise ValueError(f"synthetic datasets refused for evaluation: {synthetic}")
    attack_runs = [r for r in reports if any(a.attack_sources for a in r.arms)]
    per_arm: dict[str, dict[str, list[float]]] = {}
    for rep in attack_runs:
        for a in rep.arms:
            vals = per_arm.setdefault(a.arm, {k: [] for k in METRICS})
            row = {
                "recall": a.recall,
                "fpr": a.fpr,
                "containment": a.attack_sources_contained / a.attack_sources
                if a.attack_sources
                else None,
                "median_detection_latency_s": a.median_detection_latency_s,
                "legit_request_success": a.legit_request_success,
            }
            for k, v in row.items():
                if v is not None:
                    vals[k].append(float(v))
    arms = {
        arm: {
            k: {
                "mean": round(float(np.mean(v)), 4) if v else None,
                "ci95_over_runs": _ci(v, seed),
                "n_runs": len(v),
            }
            for k, v in vals.items()
        }
        for arm, vals in per_arm.items()
    }
    return {
        "label": "SYNTHETIC - NOT A RESULT" if synthetic else "lab runs",
        "synthetic_datasets": synthetic,
        "n_attack_runs": len(attack_runs),
        "runs": [r.dataset_id for r in attack_runs],
        "scenarios": sorted({r.scenario for r in attack_runs}),
        "ci_note": f"95 % bootstrap over runs; omitted below {MIN_RUNS_FOR_CI} runs",
        "arms": arms,
    }
