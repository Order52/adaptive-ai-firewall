"""Reproducibility of the A3 retraining against the P7 pickles (reported, not a criterion).

Byte sha256 differs (random model/profile ids, snapshot artifact paths, measured latency
in validation metrics, non-deterministic sklearn pickles), so behaviour is compared:
every detector's scores on the same 3000 random inputs.
usage: repro_check.py   (from the repo root)
"""
import pickle
from pathlib import Path

import numpy as np

A3 = Path("artifacts/evidence/a3-2026-10-29/select")
P7 = Path("artifacts/evidence/p7-2026-10-28/select")
for n in ["R2", "R3", "D", "F", "C", "S", "FS"]:
    a = pickle.load(open(P7 / f"cand-{n}.pkl", "rb"))
    b = pickle.load(open(A3 / f"cand-{n}.pkl", "rb"))
    out = []
    for x, y in zip(a.models, b.models, strict=True):
        dx, dy = x.detector, y.detector
        est = [(k, v) for k, v in vars(dx).items() if hasattr(v, "score_samples")]
        arr = [(k, v) for k, v in vars(dx).items() if isinstance(v, np.ndarray)]
        same_arr = all(np.array_equal(v, getattr(dy, k)) for k, v in arr)
        diff = 0.0
        for k, v in est:
            X = np.random.default_rng(0).normal(size=(3000, v.n_features_in_)) * 3
            diff = max(diff, float(np.abs(v.score_samples(X) - getattr(dy, k).score_samples(X)).max()))
        out.append(f"{type(dx).__name__}: arrays equal {same_arr}, max score diff {diff}")
    print(n, "|", "; ".join(out))
