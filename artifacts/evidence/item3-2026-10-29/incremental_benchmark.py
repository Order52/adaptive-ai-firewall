"""Item 3 benchmark, SYNTHETIC feature windows only (no traffic, no team data).

It shows the *mechanics* of batch versus incremental supervised learning under delayed
verified labels: adaptation to concept drift and retention of a family that disappears
for a long stretch. It says nothing about detecting real attacks; that needs the team's
labelled runs (TEAM_ATTACK_QUICKSTART.md), and the same harness then runs on them.

usage: uv run python artifacts/evidence/item3-2026-10-29/incremental_benchmark.py <out.json>
"""
import datetime as dt
import json
import random
import sys
import time
from ipaddress import IPv4Address

from afw.domain.features import FEATURE_NAMES, FeatureVector
from afw.ml import incremental as inc

T0 = dt.datetime(2026, 10, 29, 0, 0, tzinfo=dt.UTC)
N = 6000  # windows, 5 s apart (~8.3 h)
DELAY_S = 600  # labels verified 10 min after the window


def fv(i, centre, rng):
    end = T0 + dt.timedelta(seconds=5 * i)
    return FeatureVector(
        app_id="rental", source_ip=IPv4Address(f"10.77.20.{100 + i % 60}"),
        window_start=end - dt.timedelta(seconds=30), window_end=end, n_requests=10,
        values={n: centre + rng.gauss(0, 4) for n in FEATURE_NAMES})


def scenario(name, seed=0):
    rng = random.Random(seed)
    out = []
    for i in range(N):
        seg = f"seg{5 * i // N + 1}"  # five equal segments
        r = rng.random()
        if name == "drift":  # bruteforce shifts at the midpoint
            fam = "benign" if r < 0.7 else "bruteforce" if r < 0.85 else "scan"
            c = {"benign": 0, "bruteforce": 12 if i < N // 2 else 26, "scan": 40}[fam]
        elif name == "forgetting":  # scan only in segments 1 and 5
            present = seg in ("seg1", "seg5")
            fam = "benign" if r < 0.7 else "bruteforce" if (r < 0.85 or not present) else "scan"
            c = {"benign": 0, "bruteforce": 12, "scan": 26}[fam]
        else:
            fam = "benign" if r < 0.7 else "bruteforce" if r < 0.85 else "scan"
            c = {"benign": 0, "bruteforce": 12, "scan": 26}[fam]
        out.append(inc.StreamItem(fv(i, c, rng), fam, seg))
    return out


report = {"SYNTHETIC": True, "windows": N, "label_delay_s": DELAY_S, "scenarios": {}}
for sc in ("stationary", "drift", "forgetting"):
    s = scenario(sc)
    res = {}
    t = time.time()
    res["rf_batch"] = inc.batch_prequential(s, label_delay_s=DELAY_S, refit_every=500,
                                            synthetic=True).as_dict()
    res["rf_batch"]["seconds"] = round(time.time() - t, 1)
    for kind, reh in (("arf", True), ("hat", True), ("arf", False)):
        t = time.time()
        rep, _ = inc.prequential(
            s, kind=kind, label_delay_s=DELAY_S, checkpoint_every=10**9, synthetic=True,
            rehearsal=None if reh else inc.Rehearsal(per_family=0))
        key = kind + ("" if reh else "_no_rehearsal")
        res[key] = rep.as_dict() | {"seconds": round(time.time() - t, 1)}
    report["scenarios"][sc] = res
    print(sc, {k: v["recall_by_dataset"] for k, v in res.items()}, flush=True)
json.dump(report, open(sys.argv[1], "w"), indent=1, default=str)
