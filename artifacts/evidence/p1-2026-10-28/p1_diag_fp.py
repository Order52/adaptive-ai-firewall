"""P1 diagnosis: why does the trusted v2 profile flag later benign runs? (read-only)"""

import json
import sys
from collections import Counter, defaultdict

import numpy as np

from afw.config import get_settings
from afw.container import build_container
from afw.domain.features import FEATURE_NAMES
from afw.services.learning import _rows

c = build_container(get_settings(), simulated=True, migrate=False)
prof, models = c.learning.load_active("rental")
cat = c.learning.catalog("rental", prof)
med = np.array([prof.features[f].median if hasattr(prof.features[f], "median") else 0.0 for f in FEATURE_NAMES]) if isinstance(getattr(prof, "features", None), dict) else None
out = {"profile": prof.version, "models": {}}

DS = sys.argv[1].split(",")
train_rows = None
for ds in DS:
    m = c.datasets.manifest(ds)
    obs = c.datasets.observations(ds)
    vecs = c.learning.windows(obs, cat)
    X = _rows(vecs)
    srcs = np.array([str(v.source_ip) for v in vecs])
    rec = {"purpose": m.purpose.value, "start": m.start.isoformat(), "end": m.end.isoformat(),
           "observations": len(obs), "windows": len(vecs),
           "sources": len(set(srcs))}
    dur = max((m.end - m.start).total_seconds(), 1)
    per_src = Counter(str(o.client_ip) for o in obs)
    rec["req_per_source_per_min"] = round(float(np.mean(list(per_src.values()))) / dur * 60, 2)
    for lm in models:
        r = lm.record
        s = lm.detector.score(X)
        flag = s >= r.threshold
        by = defaultdict(list)
        for sv, f in zip(srcs, flag):
            by[sv].append(f)
        drivers = Counter()
        if flag.any() and med is None:
            base = np.median(train_rows, axis=0) if train_rows is not None else np.median(X, axis=0)
        else:
            base = np.median(train_rows, axis=0) if train_rows is not None else np.median(X, axis=0)
        for i in np.where(flag)[0][:400]:
            row = X[i : i + 1].repeat(len(FEATURE_NAMES), axis=0)
            for j in range(len(FEATURE_NAMES)):
                row[j, j] = base[j]
            drop = s[i] - lm.detector.score(row)
            drivers[FEATURE_NAMES[int(np.argmax(drop))]] += 1
        rec[r.detector.value] = {
            "window_fpr": round(float(flag.mean()), 4),
            "per_source_fpr": {k: round(float(np.mean(v)), 3) for k, v in sorted(by.items())},
            "top_driver_counts": dict(drivers.most_common(5)),
        }
    q = {f: [round(float(x), 3) for x in np.quantile(X[:, j], [0.5, 0.95])] for j, f in enumerate(FEATURE_NAMES)}
    rec["feature_q50_q95"] = q
    if train_rows is None:
        train_rows = X  # first dataset = training reference
    out[ds] = rec
print(json.dumps(out, indent=1, default=str))
