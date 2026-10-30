"""P2: why does the adapted challenger flag fewer attack-like probes? (read-only replay)"""

import json
import tempfile
from pathlib import Path

import numpy as np

from afw.config import get_settings
from afw.container import build_container
from afw.ml.adaptation_experiment import RELAXED, _challenger
from afw.ml.challenger_gate import tumbling
from afw.ml.online_replay import learn_stream
from afw.profiling.eligibility import SENSITIVE

c = build_container(get_settings(), simulated=True, migrate=False)
cfg = c.cfg
prof, models = c.learning.load_active("rental")
cat = c.learning.catalog("rental", prof)
learn = c.datasets.observations("real-drift-learn-20261027")
hold_obs = c.datasets.observations("real-drift-hold-20261027")
indist_obs = c.datasets.observations("real-benign-train")  # 10-17 held-out test run (v2 regime)

st = learn_stream(cfg=cfg, profile=prof, models=models, catalog=cat, learn=learn,
                  learning=cfg.learning.model_copy(update=RELAXED), work_dir=Path(tempfile.mkdtemp()))
hst, ch = st.champion, _challenger(st)
thr = hst.record.threshold
C, H = hst.detector, ch.detector
_FR = {"auth_fail_frac", "client_err_frac"}


def rows(ws):
    return np.array([w.as_row() for w in ws], dtype=float)


def probe(ws, name):
    q99 = prof.features[name].q99
    v = min(1.0, max(2 * q99, 0.5)) if name in _FR else max(2 * q99, q99 + 1.0)
    return [w.model_copy(update={"values": {**w.values, name: v}}) for w in ws]


def analyse(label, ws):
    X = rows(ws)
    bc, bh = C.score(X), H.score(X)
    nc, nh = bc < thr, bh < thr
    common = nc & nh
    res = {"bases": len(ws), "champion_normal": int(nc.sum()), "challenger_normal": int(nh.sum()),
           "common_normal": int(common.sum()),
           "median_base_margin": {"champion": round(float(np.median(thr - bc[nc])), 4) if nc.any() else None,
                                  "challenger": round(float(np.median(thr - bh[nh])), 4) if nh.any() else None}}
    per = {}
    for f in SENSITIVE:
        P = rows(probe(ws, f))
        pc, ph = C.score(P), H.score(P)
        d = {
            "own_normal_rate": {"champion": round(float((pc[nc] >= thr).mean()), 3) if nc.any() else None,
                                "challenger": round(float((ph[nh] >= thr).mean()), 3) if nh.any() else None},
            "common_normal_rate": {"champion": round(float((pc[common] >= thr).mean()), 3) if common.any() else None,
                                   "challenger": round(float((ph[common] >= thr).mean()), 3) if common.any() else None},
            "median_score_increase_common": {
                "champion": round(float(np.median(pc[common] - bc[common])), 4) if common.any() else None,
                "challenger": round(float(np.median(ph[common] - bh[common])), 4) if common.any() else None},
        }
        # margin-matched: champion-normal and challenger-normal bases binned by distance to threshold
        bins = [0, 0.02, 0.05, 0.1, 1.0]
        mm = {}
        for lo, hi in zip(bins, bins[1:]):
            sc = nc & (thr - bc >= lo) & (thr - bc < hi)
            sh = nh & (thr - bh >= lo) & (thr - bh < hi)
            mm[f"{lo}-{hi}"] = {
                "champion": [round(float((pc[sc] >= thr).mean()), 3) if sc.any() else None, int(sc.sum())],
                "challenger": [round(float((ph[sh] >= thr).mean()), 3) if sh.any() else None, int(sh.sum())]}
        d["by_base_margin"] = mm
        per[f] = d
    res["per_feature"] = per
    return res


hold = tumbling(list(c.learning.windows(hold_obs, cat)))
indist = tumbling(list(c.learning.windows(indist_obs, cat)))
learned = st.learner.repo.lineage(hst.record.app_id, hst.record.model_id, ch.n_learned)
lw = {w.fingerprint for w in learned}
lwin = [w for w in st.windows if True]
out = {
    "threshold": thr, "n_learned": ch.n_learned,
    "drift_holdout": analyse("drift_holdout", hold),
    "in_distribution_10_17": analyse("indist", indist),
}
# Sensitive-feature distribution of what was learned vs v2 training (scaled HST space)
tr = list(c.learning.windows(c.datasets.observations("real-benign-train2"), cat))
fp_of = __import__("afw.ml.online", fromlist=["fingerprint"]).fingerprint
lrn = [w for w in st.windows if fp_of(w) in lw]
from afw.domain.features import FEATURE_NAMES
idx = {n: i for i, n in enumerate(FEATURE_NAMES)}
dist = {}
for f in SENSITIVE:
    a = rows(tr)[:, idx[f]] if tr else np.array([])
    b = rows(lrn)[:, idx[f]] if lrn else np.array([])
    dist[f] = {"q99_profile": prof.features[f].q99,
               "train_q50_q90_max": [round(float(x), 3) for x in np.quantile(a, [0.5, 0.9, 1.0])] if len(a) else None,
               "learned_q50_q90_max": [round(float(x), 3) for x in np.quantile(b, [0.5, 0.9, 1.0])] if len(b) else None}
out["sensitive_distribution"] = dist
out["n_learned_windows_matched"] = len(lrn)
print(json.dumps(out, indent=1))
