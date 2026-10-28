"""SV-1: does occlusion wrongly call a behaviour anomaly independent of AUTH evidence?

usage: sv1_counterfactual.py <snapshot_dir> <dataset> <out.json>
Synthetic brute-force/stuffing requests are added to real benign base windows that the
detector scores NORMAL. Any anomaly of the resulting window is therefore caused by the
added requests, which are exactly the requests that also produce AUTH evidence: the
true answer to "is the behaviour anomaly independent of AUTH?" is NO for every case.
False-independence rate = share of (flagged, AUTH-evidence) cases where occlusion
(the controller's check, ADR-027) says independent. Offline, no traffic.

Second part (after the fix): the same cases scored by the residual verdict
(``_independent_of`` with the window's residuals), plus INDEPENDENT cases: brute force
plus scraping on the same base, kept only where base+scraping without any failed
login is flagged, so the true answer is YES. (The residual verdict computes exactly
that window, so its zero here is a consistency check; the informative numbers are
the occlusion errors.) Reported for both verdicts: false independence on dependent
cases and false dependence on independent cases.
"""
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import numpy as np

from afw.config import Settings
from afw.container import build_container
from afw.correlation.engine import CorrelationEngine
from afw.domain.risk import EVIDENCE_FEATURES, EvidenceCategory
from afw.features.extract import _auth_evidence_request, compute_features
from afw.ml import p6_study as st
from afw.ml import regression_suite as rs
from afw.ml.challenger_gate import tumbling
from afw.ml.inference import _independent_of
from afw.ml.registry import ArtifactStore

snap, ds, out = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
_load = ArtifactStore.load
ArtifactStore.load = lambda self, r: _load(self, r.model_copy(update={"artifact_path": r.artifact_path.replace("/var/lib/afw/", f"{snap}/")}))
c = build_container(Settings(config=Path("config/lab.yaml"), data_dir=snap), simulated=True, migrate=False)
L = c.learning
prof, models = L.load_version("rental", 2)
cands = [st.Candidate("R2", prof, models, L.catalog("rental", prof))]
if len(sys.argv) > 4:  # extra: a trained candidate D on the given train/val lists
    tr, va = sys.argv[4].split(","), sys.argv[5].split(",")
    cands.append(st.train("D", L, "rental", tr, va, ArtifactStore(snap / "p6-scratch-models"), created_at=datetime(2026, 10, 28, tzinfo=UTC)))
obs = c.datasets.observations(ds)
bases = rs.bases(tumbling(L.windows(obs, cands[0].catalog)), obs)
auth = EVIDENCE_FEATURES[EvidenceCategory.AUTH]
eng = CorrelationEngine(c.cfg.risk)
report = {"dataset": ds, "bases": len(bases), "candidates": {}}
for cand in cands:
    res = {}
    for m in cand.models:
        det, thr = m.detector, m.record.threshold
        base_rows = np.array([compute_features(list(b.observations), c.cfg.window, cand.catalog, b.start, b.end).as_row() for b in bases])
        normal = np.asarray(det.score(base_rows)) < thr
        per = {}
        for fam in ("brute_force", "stuffing"):
            for k in (5, 10, 20):
                n_case = flagged = with_auth = occl_indep = resid_indep = 0
                for b, ok in zip(bases, normal):
                    if not ok:
                        continue
                    fv = rs.case_window(fam, k, b, c.cfg.window, cand.catalog)
                    n_case += 1
                    row = np.array(fv.as_row(), dtype=float)
                    if det.score(row[None, :])[0] < thr:
                        continue
                    flagged += 1
                    if not eng._auth(fv):
                        continue
                    with_auth += 1
                    occl_indep += bool(det.anomalous_without(row, auth, thr))
                    resid_indep += "auth" in _independent_of(det, row, thr, fv)
                per[f"{fam}@{k}"] = {"cases": n_case, "flagged": flagged, "flagged_with_auth_evidence": with_auth,
                                     "occlusion_says_independent": occl_indep,
                                     "false_independence_rate": round(occl_indep / with_auth, 4) if with_auth else None,
                                     "residual_says_independent": resid_indep,
                                     "residual_false_independence_rate": round(resid_indep / with_auth, 4) if with_auth else None}
        for k in (10, 20):
            for ks in (40, 80):
                n_ind = occl_dep = resid_dep = 0
                for b, ok in zip(bases, normal):
                    if not ok:
                        continue
                    scr = rs.synthetic("scraping", ks, b)
                    # ground truth: everything except the requests behind AUTH evidence
                    # (the base's own failed logins included) is anomalous on its own
                    keep = [o for o in b.observations if not _auth_evidence_request(o, cand.catalog)]
                    alone = compute_features(sorted([*keep, *scr], key=lambda o: o.observed_at), c.cfg.window, cand.catalog, b.start, b.end)
                    if det.score(np.array(alone.as_row(), dtype=float)[None, :])[0] < thr:
                        continue  # not independently anomalous: no ground truth YES
                    mix = sorted([*b.observations, *scr, *rs.synthetic("brute_force", k, b)], key=lambda o: o.observed_at)
                    fv = compute_features(mix, c.cfg.window, cand.catalog, b.start, b.end)
                    row = np.array(fv.as_row(), dtype=float)
                    if det.score(row[None, :])[0] < thr or not eng._auth(fv):
                        continue
                    n_ind += 1
                    occl_dep += not det.anomalous_without(row, auth, thr)
                    resid_dep += "auth" not in _independent_of(det, row, thr, fv)
                per[f"brute_force@{k}+scraping@{ks}"] = {"independent_cases": n_ind,
                    "occlusion_false_dependence_rate": round(occl_dep / n_ind, 4) if n_ind else None,
                    "residual_false_dependence_rate": round(resid_dep / n_ind, 4) if n_ind else None}
        res[m.record.detector.value] = {"bases_normal": int(normal.sum()), "cases": per}
    report["candidates"][cand.name] = res
out.write_text(json.dumps(report, indent=1))
for cn, r in report["candidates"].items():
    for d, x in r.items():
        print(cn, d, "normal bases", x["bases_normal"])
        for k, v in x["cases"].items():
            print("   ", k, {a: b for a, b in v.items() if "rate" in a or "cases" in a or "with_auth" in a})
