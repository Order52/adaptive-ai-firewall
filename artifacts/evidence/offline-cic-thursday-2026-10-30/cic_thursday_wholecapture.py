"""Whole-capture static-vs-ML on Thursday with ML that NEVER saw Thursday (trained on Tuesday+
Friday), split by time of day so the family mix is visible. Fair static baseline (HOME_NET =
victim LAN only). Compromised hosts excluded. Offline, separate gate.
usage: cic_thursday_wholecapture.py <out.json>"""
import json, os, pickle, sys
from datetime import timedelta, timezone
from pathlib import Path
import numpy as np
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "offline-cic-2026-10-29"))
from cic_audit import BEHAVIOUR, groups_idx  # noqa: E402
from cic_offline_eval import FEATURE_NAMES  # noqa: E402
from cic_robustness import cached_build  # noqa: E402
from cic_static_vs_ml import load_alerts  # noqa: E402
AX = Path.home() / "afw-external-datasets"
ATT = {"172.16.0.1", "205.174.165.73", "205.174.165.80"}; EXC = {"192.168.10.8", "192.168.10.25"}
names = list(FEATURE_NAMES); beh = groups_idx(names, BEHAVIOUR)
X, y, times, srcs, _ = cached_build("", "thursday")
y = np.array([int(s in ATT) for s in srcs]); keep = np.array([s not in EXC for s in srcs])
X, y = X[keep][:, beh], y[keep]; srcs = [s for s, k in zip(srcs, keep) if k]; times = [t for t, k in zip(times, keep) if k]
Xt, yt, *_ = pickle.load(open(AX / "cache/tuesday.pkl", "rb")); Xf, yf, *_ = pickle.load(open(AX / "cache/friday.pkl", "rb"))
from sklearn.ensemble import RandomForestClassifier
rf = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0, n_jobs=-1).fit(np.vstack([Xt[:, beh], Xf[:, beh]]), np.concatenate([yt, yf]))
ml = rf.predict(X)
alerts, _, _ = load_alerts(str(AX / "cic-ids2017/Thursday-fair-out/eve.json"))
def hit(i, attack_only=True):
    a = alerts.get(srcs[i]);  lo = times[i] - timedelta(seconds=60)
    return int(bool(a) and any(lo <= t <= times[i] and (m or not attack_only) for t, m in a))
st = np.array([hit(i) for i in range(len(y))])
hour = np.array([t.astimezone(timezone.utc).hour for t in times])
def rate(p, m): return round(float(p[m].mean()), 4) if m.any() else None
def block(label, m):
    a = (y == 1) & m; b = (y == 0) & m
    return {"attack_windows": int(a.sum()), "static_recall": rate(st, a), "ml_recall": rate(ml, a),
            "union_recall": rate(((st == 1) | (ml == 1)).astype(int), a),
            "only_static": int(((st == 1) & (ml == 0) & a).sum()), "only_ml": int(((ml == 1) & (st == 0) & a).sum()),
            "both": int(((st == 1) & (ml == 1) & a).sum()), "neither": int(((st == 0) & (ml == 0) & a).sum()),
            "benign_windows": int(b.sum()), "static_fpr": rate(st, b), "ml_fpr": rate(ml, b),
            "union_fpr": rate(((st == 1) | (ml == 1)).astype(int), b)}
rep = {"note": "ML trained on Tuesday+Friday only (never saw Thursday); static = ET Open 2026 ruleset, fair HOME_NET; compromised hosts excluded",
       "whole_day": block("all", np.ones(len(y), bool)),
       "morning_UTC<14 (web attacks)": block("am", hour < 14), "afternoon_UTC>=14": block("pm", hour >= 14)}
json.dump(rep, open(sys.argv[1], "w"), indent=1)
for k, v in rep.items():
    if isinstance(v, dict): print(f"{k:30} atk={v['attack_windows']:4}  static={v['static_recall']}  ML={v['ml_recall']}  union={v['union_recall']}  | only-static={v['only_static']} only-ML={v['only_ml']} both={v['both']} neither={v['neither']} | FPR static={v['static_fpr']} ML={v['ml_fpr']} union={v['union_fpr']}")
