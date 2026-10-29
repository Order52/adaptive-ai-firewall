"""NV2 driver (protocol docs/engineering/NV2_NETWORK_NOVELTY_REVALIDATION.md); nv1_eval.py
with the NV2 datasets and the reported-only NV1-ceiling comparison (§4).

usage: nv2_eval.py <snapshot_dir> dev  <out.json> [logs_dir]
         calibrate on nv2-train, measure on nv2-val (development, may be repeated);
         writes <out>.calibration.json with its sha256 alongside
       nv2_eval.py <snapshot_dir> test <out.json> <calibration.json> <sha256> [logs_dir]
         the frozen calibration (sha256 checked), measured once on the nv2-test and
         nv2-test-shift users (unseen)
Runs offline against a read-only snapshot of CTRL01's data directory.
"""
import hashlib
import json
import re
import sys
from collections import Counter
from ipaddress import IPv4Address
from pathlib import Path

import numpy as np

from afw.config import Settings
from afw.container import build_container
from afw.features.network import FEATURE_NAMES
from afw.ml.adaptation_experiment import source_ci
from afw.ml.network_detector import NetworkNovelty, calibration_windows

snap, stage, out = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
c = build_container(Settings(config=Path("config/lab.yaml"), data_dir=snap), simulated=True, migrate=False)
services = [(s.address, s.port) for s in c.cfg.services]

_HABIT = re.compile(r"^net (\S+): (\w+) ")


def habits(logs: Path | None) -> dict[IPv4Address, str]:
    out: dict[IPv4Address, str] = {}
    for p in sorted(logs.glob("*.log")) if logs else []:
        for line in p.read_text(errors="replace").splitlines():
            m = _HABIT.match(line)
            if m:
                out[IPv4Address(m.group(1))] = m.group(2)
    return out


def windows(datasets):
    vs, info = [], {}
    for ds in datasets:
        m = c.datasets.manifest(ds)
        w = calibration_windows(m, c.datasets.net_events(ds), services)
        info[ds] = {"net_events": m.n_net_events, "windows": len(w),
                    "nonzero": sum(v.n_events > 0 for v in w)}
        vs += w
    return vs, info


def measure(det, vs, hab):
    verdicts = [det.assess(v) for v in vs]
    unf = np.array([x.unfamiliar for x in verdicts])
    strong = np.array([x.strong for x in verdicts])
    r = source_ci(vs, unf)
    per = r.pop("per_source")
    s = source_ci(vs, strong)
    s.pop("per_source")
    drivers = Counter()
    for x in verdicts:
        for reason in x.reasons:
            drivers[reason.split("=")[0]] += 1
    by_habit = {}
    for ip, share in per.items():
        by_habit.setdefault(hab.get(IPv4Address(ip), "unknown"), []).append(share)
    return {
        "unfamiliar": r,
        "strong": s,
        "users_with_strong": sorted({x.source_ip for x in verdicts if x.strong}),
        "per_user_unfamiliar_share": per,
        "by_habit_mean_share": {h: round(float(np.mean(v)), 4) for h, v in by_habit.items()},
        "drivers": dict(drivers.most_common()),
        # reported only (§4): windows the NV1 dst_hosts_60 ceiling (10) would have made strong
        "nv1_dst_hosts_ceiling_share": round(
            float(np.mean([v.values["dst_hosts_60"] >= 10 for v in vs])) if vs else 0.0, 4),
    }


def criteria(m):
    why = []
    u = m["unfamiliar"]
    if u["rate"] is None or u["rate"] > 0.02 or u["ci95"][1] > 0.05:
        why.append(f"unfamiliar FPR {u['rate']} ci {u['ci95']}")
    if m["users_with_strong"]:
        why.append(f"strong verdict for {m['users_with_strong']}")
    return {"pass": not why, "why": why}


report = {"stage": stage}
if stage == "dev":
    logs = Path(sys.argv[4]) if len(sys.argv) > 4 else None
    train, tinfo = windows(["nv2-train"])
    det = NetworkNovelty()
    det.calibrate(train)
    cal = det.to_dict() | {"datasets": ["nv2-train"], "effective": det.effective()}
    blob = json.dumps(cal, indent=2, sort_keys=True).encode()
    cpath = out.with_suffix(".calibration.json")
    cpath.write_bytes(blob)
    report["calibration"] = {"path": cpath.name, "sha256": hashlib.sha256(blob).hexdigest(),
                             "data": tinfo, "effective": cal["effective"]}
    x = np.array([v.as_row() for v in train])
    report["calibration"]["nonzero_share_per_quantity"] = {
        n: round(float((x[:, i] > 0).mean()), 4) for i, n in enumerate(FEATURE_NAMES)}
    val, vinfo = windows(["nv2-val"])
    report["val"] = {"data": vinfo} | measure(det, val, habits(logs))
    report["val"]["criteria_if_this_were_the_test"] = criteria(report["val"])
elif stage == "test":
    cpath, sha = Path(sys.argv[4]), sys.argv[5]
    logs = Path(sys.argv[6]) if len(sys.argv) > 6 else None
    blob = cpath.read_bytes()
    if hashlib.sha256(blob).hexdigest() != sha:
        raise SystemExit("calibration does not match the frozen sha256")
    det = NetworkNovelty()
    det.load(json.loads(blob))
    test, info = windows(["nv2-test", "nv2-test-shift"])
    report["frozen"] = {"path": str(cpath), "sha256": sha}
    report["test"] = {"data": info} | measure(det, test, habits(logs))
    report["criteria"] = criteria(report["test"])
else:
    raise SystemExit("stage is dev or test")
out.write_text(json.dumps(report, indent=1, default=str))
print(json.dumps({k: v for k, v in report.items() if k != "calibration"}, indent=1, default=str)[:4000])
