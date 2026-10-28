"""P6 post-selection diagnosis (selection data only; Phase E untouched).

usage: diagnose_restrictions.py <snapshot_dir> <select_dir> <out.json> <cand,...>
For each candidate pickle, replays M2 on p6-sel and p6-sel-shift and records every
traffic-affecting intent for a benign source: its kind, reason codes and the
corroborating categories, so the restriction path can be attributed.
"""
import collections, hashlib, json, pickle, sys
from pathlib import Path

from afw.config import Settings
from afw.container import build_container
from afw.ml import p6_study as st
from afw.ml.registry import ArtifactStore
from afw.policy import decision as dmod

snap, sel, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
names = sys.argv[4].split(",")
_load = ArtifactStore.load
ArtifactStore.load = lambda self, r: _load(self, r.model_copy(update={"artifact_path": r.artifact_path.replace("/var/lib/afw/", f"{snap}/")}))
c = build_container(Settings(config=Path("config/lab.yaml"), data_dir=snap), simulated=True, migrate=False)
L, cfg = c.learning, c.cfg

rec = []
_decide = dmod.DecisionEngine.decide
def decide(self, ra, prior_blocks, now):
    it = _decide(self, ra, prior_blocks, now)
    if it is not None and it.kind.value != "watch":
        cats = sorted(str(x) for x in ra.corroborating_categories)
        ev = sorted({str(e.category) for e in ra.evidence if e.points > 0})
        rec.append({"ip": str(ra.source_ip), "kind": it.kind.value, "score": ra.score,
                    "corroborating": cats, "evidence": ev,
                    "codes": [x for x in it.reason_codes if not x.startswith("escalation")]})
    return it
dmod.DecisionEngine.decide = decide

arche = st.archetypes(sorted((snap.parent / "logs").glob("*.log"))) if (snap.parent / "logs").exists() else {}
res = {}
for n in names:
    blob = (sel / f"cand-{n}.pkl").read_bytes()
    meta = json.loads((sel / f"cand-{n}.json").read_text())
    assert hashlib.sha256(blob).hexdigest() == meta["sha256"]
    cand = pickle.loads(blob)
    for ds in ("p6-sel", "p6-sel-shift"):
        rec.clear()
        st.benign_eval(cand, L, cfg, c.datasets.manifest(ds), c.datasets.observations(ds), {})
        users = collections.defaultdict(collections.Counter)
        for r in rec:
            path = "+".join(r["corroborating"]) + (" [detectors agree]" if set(r["evidence"]) >= {"behavior_ml", "behavior_stat"} else "")
            users[r["ip"]][f'{r["kind"]}: {path}'] += 1
        res[f"{n}/{ds}"] = {"restricted_users": len(users), "intents": len(rec),
                            "paths": dict(collections.Counter(k for u in users.values() for k in u)),
                            "per_user": {u: dict(v) for u, v in users.items()}}
        print(n, ds, len(users), dict(collections.Counter(k for u in users.values() for k in u)), flush=True)
out.write_text(json.dumps(res, indent=1))
