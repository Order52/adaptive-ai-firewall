"""Run-level uncertainty and tool-artefact / timing ablation (offline, separate gate).

WHY: window-level Wilson CIs treat windows as independent. They are not: windows overlap
(300 s horizon, 30 s step) and every attack family here is ONE attacker session. So the
honest sample size is the number of independent attack BURSTS, not windows. This script
reports (1) block-bootstrap CIs (resample whole 10-minute time blocks) and (2) the number
of independent attack bursts, and (3) a feature-GROUP ablation that tests reliance on
timing, DNS-absence (a tool artefact), volume, failures and port/host identity.

usage: cic_robustness.py <eve.json> <label> <out.json>
"""
import json
import pickle
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from cic_offline_eval import FEATURE_NAMES, build  # noqa: E402

CACHE = Path.home() / "afw-external-datasets" / "cache"
BLOCK_S = 600  # resample whole 10-minute blocks
BURST_GAP_S = 600  # attack windows more than 10 min apart are separate bursts

GROUPS = {
    "timing": {"median_duration_s"},
    "dns": {"dns_queries", "dns_nxdomain", "dns_names"},
    "volume": {"flows", "bytes_out_log", "udp_flows", "icmp_flows"},
    "failures": {"failed"},
    "identity(port/host/fanout)": {"ssh_flows", "dst_hosts", "sweep_hosts", "dst_ports", "max_ports_per_host"},
}


def cols(names, bases):
    return [i for i, n in enumerate(names) if n.rsplit("_", 1)[0] in bases]


def cached_build(eve, label):
    CACHE.mkdir(parents=True, exist_ok=True)
    p = CACHE / f"{label}.pkl"
    if p.exists():
        return pickle.load(open(p, "rb"))
    out = build(eve)
    pickle.dump(out, open(p, "wb"))
    return out


def metrics(y, p):
    tp = int(((p == 1) & (y == 1)).sum()); fn = int(((p == 0) & (y == 1)).sum())
    fp = int(((p == 1) & (y == 0)).sum()); tn = int(((p == 0) & (y == 0)).sum())
    return tp, fn, fp, tn


def block_bootstrap(y, p, ts, n_boot=2000, seed=0):
    """Resample whole time blocks; returns recall / FPR percentile CIs."""
    blk = (ts // BLOCK_S).astype(int)
    ids = np.unique(blk)
    per = {b: metrics(y[blk == b], p[blk == b]) for b in ids}
    rng = np.random.RandomState(seed)
    rec, fpr = [], []
    for _ in range(n_boot):
        pick = rng.choice(ids, size=len(ids), replace=True)
        tp = sum(per[b][0] for b in pick); fn = sum(per[b][1] for b in pick)
        fp = sum(per[b][2] for b in pick); tn = sum(per[b][3] for b in pick)
        if tp + fn:
            rec.append(tp / (tp + fn))
        if fp + tn:
            fpr.append(fp / (fp + tn))
    ci = lambda a: [round(float(np.percentile(a, 2.5)), 4), round(float(np.percentile(a, 97.5)), 4)] if a else [None, None]  # noqa: E731
    return {"recall_ci95_block": ci(rec), "fpr_ci95_block": ci(fpr), "n_blocks": int(len(ids)),
            "n_blocks_with_attack": int(sum(1 for b in ids if per[b][0] + per[b][1] > 0))}


def bursts(ts, y):
    t = np.sort(ts[y == 1])
    if not len(t):
        return 0
    return int(1 + (np.diff(t) > BURST_GAP_S).sum())


def main():
    eve, label, out = sys.argv[1], sys.argv[2], sys.argv[3]
    X, y, times, srcs, _ = cached_build(eve, label)
    names = list(FEATURE_NAMES)
    ts = np.array([t.timestamp() for t in times])
    order = np.argsort(ts)
    X, y, ts = X[order], y[order], ts[order]
    from sklearn.ensemble import RandomForestClassifier

    cut = int(0.6 * len(y))
    # 300 s gap so train/test windows do not overlap
    start = next((j for j in range(cut, len(y)) if ts[j] - ts[cut] >= 300), cut)
    tr, te = slice(0, cut), slice(start, len(y))
    rep = {"label": label, "windows": int(len(y)), "attack_windows": int(y.sum()),
           "independent_attack_bursts_total": bursts(ts, y),
           "independent_attack_bursts_in_test": bursts(ts[te], y[te]),
           "note": ("effective sample size = independent bursts, not windows; every family here is "
                    "one attacker session, so run-level n is 1 per family"),
           "split": {"train": int(cut), "gap_dropped": int(start - cut), "test": int(len(y) - start)}}
    if not (y[tr].sum() and y[te].sum()):
        rep["error"] = "attack missing from a split half"
        json.dump(rep, open(out, "w"), indent=1); print(json.dumps(rep, indent=1)); return

    def fit_eval(idx, tag):
        rf = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0, n_jobs=-1)
        rf.fit(X[tr][:, idx], y[tr])
        p = rf.predict(X[te][:, idx])
        tp, fn, fp, tn = metrics(y[te], p)
        r = {"recall": round(tp / (tp + fn), 4) if tp + fn else None, "fp": fp, "tn": tn,
             "fpr": round(fp / (fp + tn), 6) if fp + tn else None, "tp": tp, "fn": fn}
        r.update(block_bootstrap(y[te], p, ts[te]))
        return r

    allc = list(range(len(names)))
    beh = cols(names, GROUPS["timing"] | GROUPS["dns"] | GROUPS["volume"] | GROUPS["failures"])
    rep["all_features"] = fit_eval(allc, "all")
    rep["behaviour_only"] = fit_eval(beh, "beh")
    only, without = {}, {}
    for g, bases in GROUPS.items():
        gi = cols(names, bases)
        only[g] = fit_eval(gi, g)
        without[g] = fit_eval([i for i in allc if i not in gi], "no_" + g)
    rep["single_group_only"] = only
    rep["leave_one_group_out"] = without
    json.dump(rep, open(out, "w"), indent=1, default=str)
    print(f"[{label}] bursts total={rep['independent_attack_bursts_total']} in-test={rep['independent_attack_bursts_in_test']}")
    for k in ("all_features", "behaviour_only"):
        v = rep[k]; print(f"  {k:16} recall={v['recall']} block-CI={v['recall_ci95_block']}  fpr={v['fpr']} block-CI={v['fpr_ci95_block']}")
    print("  --- single group only ---")
    for g, v in only.items(): print(f"  {g:28} recall={v['recall']} block-CI={v['recall_ci95_block']} fpr={v['fpr']}")
    print("  --- leave one group out ---")
    for g, v in without.items(): print(f"  without {g:20} recall={v['recall']} block-CI={v['recall_ci95_block']} fpr={v['fpr']}")


if __name__ == "__main__":
    main()
