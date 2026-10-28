"""P6 driver: train candidates and evaluate them (protocol: P6_GENERALIZATION_AND_SENSITIVITY.md).

usage: p6_run.py <snapshot_dir> <stage> <out.json> [logs_dir] [frozen.pkl]
  stage smoke : D and R2 on P1 train/calibration data only (code check, no conclusions)
  stage select: all candidates on p6-sel / p6-sel-shift (selection sets); applies the
                predeclared selection rule (§6 + A1) and pickles every candidate
  stage final : the frozen selection (pickle, sha256 checked) and R2 on the Phase E sets,
                then the preserved P1 sets, once
Runs offline against a read-only snapshot of CTRL01's data directory.
"""
import hashlib
import json
import pickle
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from afw.config import Settings
from afw.container import build_container
from afw.ml import p6_study as st
from afw.ml import regression_suite as rs
from afw.ml.registry import ArtifactStore
from afw.ml.challenger_gate import tumbling

snap, stage, out = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
logs = Path(sys.argv[4]) if len(sys.argv) > 4 else None
frozen = Path(sys.argv[5]) if len(sys.argv) > 5 else None

_load = ArtifactStore.load
def _remap(self, record):  # frozen models were stored under /var/lib/afw on CTRL01
    p = record.artifact_path.replace("/var/lib/afw/", f"{snap}/")
    return _load(self, record.model_copy(update={"artifact_path": p}))
ArtifactStore.load = _remap

c = build_container(Settings(config=Path("config/lab.yaml"), data_dir=snap), simulated=True, migrate=False)
L, cfg, app = c.learning, c.cfg, "rental"
store = ArtifactStore(snap / "p6-scratch-models")
now = datetime(2026, 10, 28, 14, 0, tzinfo=UTC)
t0 = time.time()

def ref(name, v):
    prof, models = L.load_version(app, v)
    cat = L.catalog(app, prof)
    val = L._labeled(list(models[0].record.validation_dataset_ids), cat)[0]
    return st.Candidate(name, prof, models, cat, val_raw=val)

arche = st.archetypes(sorted(logs.glob("*.log"))) if logs else {}
report = {"stage": stage, "started": datetime.now(UTC).isoformat()}

if stage == "smoke":
    tr, va = ["real-benign-train2", "p1-train"], ["real-benign-val"]
    cands = [ref("R2", 2), st.train("D", L, app, tr, va, store, created_at=now),
             st.train("S", L, app, tr, va, store, security=True, created_at=now)]
    evalsets = ["p1-val"]
    stress_from = "real-benign-val"
elif stage == "final":
    blob = frozen.read_bytes()
    sel = json.loads(frozen.with_suffix(".json").read_text())
    if hashlib.sha256(blob).hexdigest() != sel["sha256"]:
        raise SystemExit("frozen candidate does not match its recorded sha256")
    chosen = pickle.loads(blob)
    cands = [ref("R2", 2), chosen] if chosen.name != "R2" else [chosen]
    evalsets = ["p6-final", "p6-final-shift", "p6-final-v1"]
    preserved = ["p1-test", "p1-shift", "real-drift-hold-20261027", "real-benign-train"]
    stress_from = "p6-val"
    report["frozen"] = sel
else:
    tr = ["real-benign-train2", "p1-train", "p6-train"]
    va = ["real-benign-val", "p1-val", "p6-val"]
    cands = [ref("R2", 2), ref("R3", 3)]
    for name, kw in [("D", {}), ("F", {"weighted": True}), ("C", {"cohorts": True}),
                     ("S", {"security": True}), ("FS", {"weighted": True, "security": True})]:
        cands.append(st.train(name, L, app, tr, va, store, created_at=now, **kw))
    evalsets = ["p6-sel", "p6-sel-shift"]
    stress_from = "p6-val"
report["candidates"] = {x.name: x.notes for x in cands}
print(f"trained in {time.time()-t0:.0f}s", flush=True)

report["benign"] = {}
for ds in evalsets:
    obs = c.datasets.observations(ds)
    man = c.datasets.manifest(ds)
    for x in cands:
        report["benign"][f"{x.name}/{ds}"] = st.benign_eval(x, L, cfg, man, obs, arche)
        print(f"benign {x.name}/{ds} {time.time()-t0:.0f}s", flush=True)

# regression suite on bases from the first evaluation set (neutral catalog: R2's)
obs = c.datasets.observations(evalsets[0])
neutral = cands[0].catalog
b = rs.bases(tumbling(L.windows(obs, neutral)), obs)
sobs = c.datasets.observations(stress_from)
sb = rs.bases(tumbling(L.windows(sobs, neutral)), sobs)
stressed = [st.stressed(x, sb, cfg.window) for x in cands]
report["stressed"] = {x.name: x.notes for x in stressed}
report["sensitivity"] = st.sensitivity([*cands, *stressed], b, cfg.window)
nom = {x.name: st.must_detect_min(report["sensitivity"], x.name) for x in cands}
strs = {x.name: st.must_detect_min(report["sensitivity"], f"{x.name}~stress") for x in cands}
report["must_detect_min"] = {"nominal": nom, "stressed": strs,
                             "selection_score": {k: min(nom[k], strs[k]) for k in nom}}

def eligible(name):
    """Selection step 1: every enforcing detector FPR <= 0.02 with upper CI <= 0.05 on
    p6-sel; M2 restricts no user on p6-sel and p6-sel-shift."""
    why = []
    det = report["benign"][f"{name}/p6-sel"]["detectors"]
    kinds = ["robust_stats", "isolation_forest"] + (["security"] if "security" in det else [])
    for k in kinds:
        r = det[k]
        if r["rate"] > 0.02 or r["ci95"][1] > 0.05:
            why.append(f"{k} fpr {r['rate']} ci {r['ci95']}")
    for ds in evalsets:
        d = report["benign"][f"{name}/{ds}"]["decision"]["M2"]
        if d["users_restricted"]:
            why.append(f"M2 restricts {d['users_restricted']}/{d['users']} users on {ds}")
    return why

if stage == "select":
    order = ["R2", "R3", "D", "C", "F", "S", "FS"]  # step 3 simplicity order
    elig = {x.name: eligible(x.name) for x in cands}
    score = report["must_detect_min"]["selection_score"]
    ok = [n for n in order if not elig[n]]
    chosen = None
    if ok:
        best = max(score[n] for n in ok)
        chosen = next(n for n in order if n in ok and best - score[n] <= 0.02)
    report["selection"] = {"ineligible_reasons": elig, "eligible": ok, "selected": chosen}
    for x in cands:
        blob = pickle.dumps(x)
        path = out.with_name(f"cand-{x.name}.pkl")
        path.write_bytes(blob)
        path.with_suffix(".json").write_text(json.dumps(
            {"name": x.name, "sha256": hashlib.sha256(blob).hexdigest(), "notes": x.notes},
            indent=1, default=str))
    print("selection:", json.dumps(report["selection"], indent=1), flush=True)

if stage == "final":
    report["preserved"] = {}
    for ds in preserved:
        obs = c.datasets.observations(ds)
        man = c.datasets.manifest(ds)
        for x in cands:
            report["preserved"][f"{x.name}/{ds}"] = st.benign_eval(x, L, cfg, man, obs, arche)

report["seconds"] = round(time.time() - t0)
out.write_text(json.dumps(report, indent=1, default=str))
print("done", report["seconds"], "s; must-detect min:", report["must_detect_min"])
