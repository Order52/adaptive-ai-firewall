"""A3 driver (P6 amendment A3, protocol docs/engineering/A3_AUTH_CONTROLS.md).

Identical to p7_run.py's select stage except:
  * replay uses the A3 code (account-aware AUTH tracker, AUTH-only view, login ladder;
    run_experiment(a3=True) is the default);
  * selection sets a3-sel / a3-sel-shift (collected after the protocol commit 7eaa8d4);
  * eligibility is A3 §5: B1 (unchanged), B2 no site-wide restriction of a legitimate
    user, B3 refused legitimate logins <= 0.5 % and <= 1 user with a login control per
    set, B4 legitimate request success >= 0.99 per set (site-wide impact + refused
    logins), and criterion 5 (SYNTHETIC attack resistance, the same for every
    candidate, run once here);
  * the retrained candidates' sha256 are compared with the P7 pickles.
Training/calibration data (p7-train, p7-val) and the stress source are unchanged.

usage: a3_run.py <snapshot_dir> select <out.json> [logs_dir]
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
from afw.ml import a3_resistance as ar
from afw.ml import p6_study as st
from afw.ml import regression_suite as rs
from afw.ml.challenger_gate import tumbling
from afw.ml.registry import ArtifactStore

snap, stage, out = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
logs = Path(sys.argv[4]) if len(sys.argv) > 4 else None
if stage != "select":
    raise SystemExit("only the select stage exists until a candidate is frozen")
P7 = Path(__file__).resolve().parent.parent / "p7-2026-10-28" / "select"

_load = ArtifactStore.load
def _remap(self, record):  # frozen models were stored under /var/lib/afw on CTRL01
    p = record.artifact_path.replace("/var/lib/afw/", f"{snap}/")
    return _load(self, record.model_copy(update={"artifact_path": p}))
ArtifactStore.load = _remap

c = build_container(Settings(config=Path("config/lab.yaml"), data_dir=snap), simulated=True, migrate=False)
L, app = c.learning, "rental"
cfg = c.cfg.model_copy(update={"safety": c.cfg.safety.model_copy(update={"behavior_only_rate_limit": False})})
store = ArtifactStore(snap / "a3-scratch-models")
now = datetime(2026, 10, 28, 14, 0, tzinfo=UTC)  # as P7, so the retrained models can match
t0 = time.time()

def ref(name, v):
    prof, models = L.load_version(app, v)
    cat = L.catalog(app, prof)
    val = L._labeled(list(models[0].record.validation_dataset_ids), cat)[0]
    return st.Candidate(name, prof, models, cat, val_raw=val)

arche = st.archetypes(sorted(logs.glob("*.log"))) if logs else {}
report = {"stage": stage, "started": datetime.now(UTC).isoformat(), "behavior_only_rate_limit": False}

tr, va = ["p7-train"], ["p7-val"]
cands = [ref("R2", 2), ref("R3", 3)]
for name, kw in [("D", {}), ("F", {"weighted": True}), ("C", {"cohorts": True}),
                 ("S", {"security": True}), ("FS", {"weighted": True, "security": True})]:
    cands.append(st.train(name, L, app, tr, va, store, created_at=now, **kw))
evalsets = ["a3-sel", "a3-sel-shift"]
stress_from = "p7-val"
report["candidates"] = {x.name: x.notes for x in cands}
print(f"trained in {time.time()-t0:.0f}s", flush=True)

# reproducibility against P7 (reported, not a criterion)
report["p7_sha256_match"] = {}
for x in cands:
    sha = hashlib.sha256(pickle.dumps(x)).hexdigest()
    p7 = P7 / f"cand-{x.name}.json"
    rec = json.loads(p7.read_text())["sha256"] if p7.exists() else None
    report["p7_sha256_match"][x.name] = {"sha256": sha, "p7": rec, "match": sha == rec}

report["benign"] = {}
for ds in evalsets:
    obs = c.datasets.observations(ds)
    man = c.datasets.manifest(ds)
    for x in cands:
        report["benign"][f"{x.name}/{ds}"] = st.benign_eval(x, L, cfg, man, obs, arche)
        print(f"benign {x.name}/{ds} {time.time()-t0:.0f}s", flush=True)

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

# criterion 5: SYNTHETIC, rule-based, identical for every candidate; evaluated once
report["attack_resistance"] = ar.run(cfg)
report["criterion5"] = ar.criterion5(report["attack_resistance"])

def eligible(name):
    """A3 §5 criteria 1-4 (criterion 5 is common to all candidates)."""
    why = []
    det = report["benign"][f"{name}/{evalsets[0]}"]["detectors"]
    kinds = ["robust_stats", "isolation_forest"] + (["security"] if "security" in det else [])
    for k in kinds:
        r = det[k]
        if r["rate"] > 0.02 or r["ci95"][1] > 0.05:
            why.append(f"B1 {k} fpr {r['rate']} ci {r['ci95']}")
    for ds in evalsets:
        d = report["benign"][f"{name}/{ds}"]["decision"]["M2"]
        if d["users_site_restricted"]:
            why.append(f"B2 site-wide restriction of {d['users_site_restricted_ips']} on {ds}")
        refused = d["login_refused"] / d["login_requests"] if d["login_requests"] else 0.0
        if refused > 0.005:
            why.append(f"B3 refused logins {d['login_refused']}/{d['login_requests']} on {ds}")
        if d["users_login_controlled"] > 1:
            why.append(f"B3 login controls on {d['users_login_controlled_ips']} on {ds}")
        b4 = 1 - (d["requests_impacted"] + d["login_refused"]) / d["requests"]
        d["B4_success"] = round(b4, 4)
        if b4 < 0.99:
            why.append(f"B4 success {b4:.4f} on {ds}")
    if not report["criterion5"]["pass"]:
        why.append("criterion 5 (attack resistance) failed")
    return why

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

report["seconds"] = round(time.time() - t0)
out.write_text(json.dumps(report, indent=1, default=str))
print("done", report["seconds"], "s; criterion 5:", report["criterion5"]["pass"])
