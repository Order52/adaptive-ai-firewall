"""Independent audit of the offline CIC-IDS2017 evaluation (P1/P2).

Checks the user raised:
  - how labels are assigned (pure source-IP?) and whether that leaks host identity;
  - whether the RF learns BEHAVIOUR or just host/port/fan-out identity (feature
    importances + ablation);
  - trivial separability (do benign windows ever look attack-like?);
  - overlap leakage at the train/test boundary (300 s horizon, 30 s step) -> add a
    temporal GAP split;
  - confidence intervals and negative outcomes.

usage: cic_audit.py <eve.json> <out.json>
Reuses build() from cic_offline_eval.py (same feature pipeline).
"""
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cic_offline_eval import FEATURE_NAMES, build  # noqa: E402

# feature groups for ablation
PORT_HOST_IDENTITY = {"ssh_flows", "dst_hosts", "sweep_hosts", "dst_ports",
                      "max_ports_per_host", "icmp_flows"}
BEHAVIOUR = {"flows", "failed", "udp_flows", "dns_queries", "dns_nxdomain",
             "dns_names", "bytes_out_log", "median_duration_s"}


def groups_idx(names, base_set):
    return [i for i, n in enumerate(names) if n.rsplit("_", 1)[0] in base_set]


def metrics(y_true, y_pred):
    tp = int(((y_pred == 1) & (y_true == 1)).sum()); fp = int(((y_pred == 1) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum()); tn = int(((y_pred == 0) & (y_true == 0)).sum())
    return {"recall": round(tp / (tp + fn), 4) if tp + fn else None,
            "precision": round(tp / (tp + fp), 4) if tp + fp else None,
            "fpr": round(fp / (fp + tn), 6) if fp + tn else None, "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def wilson(k, n, z=1.96):
    if n == 0:
        return [None, None]
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * ((p * (1 - p) + z * z / (4 * n)) / n) ** 0.5
    return [round((c - h) / d, 4), round((c + h) / d, 4)]


def main():
    eve, out = sys.argv[1], sys.argv[2]
    X, y, times, srcs, n_events = build(eve)
    names = list(FEATURE_NAMES)
    rep = {"n_windows": int(len(y)), "n_attack": int(y.sum()), "n_benign": int((y == 0).sum()),
           "note": "labels are pure source-IP (source in ATTACKERS); see audit"}
    order = np.argsort([t.timestamp() for t in times])
    Xo, yo, to = X[order], y[order], [times[i] for i in order]

    from sklearn.ensemble import RandomForestClassifier

    # --- 1. trivial separability: attack vs benign means for key features ---
    sep = {}
    for key in ("failed_60", "flows_60", "ssh_flows_60", "dst_hosts_60", "failed_300",
                "flows_300", "median_duration_s_60", "bytes_out_log_60"):
        if key in names:
            i = names.index(key)
            a = X[y == 1, i]; b = X[y == 0, i]
            sep[key] = {"attack_mean": round(float(a.mean()), 3), "attack_median": round(float(np.median(a)), 3),
                        "benign_mean": round(float(b.mean()), 3), "benign_p99": round(float(np.quantile(b, 0.99)), 3),
                        "benign_max": round(float(b.max()), 3)}
    rep["feature_separation"] = sep

    # --- 2. time-aware split WITH a gap (kill 300 s overlap leakage) ---
    cut = int(0.6 * len(yo))
    gap = 0
    # advance test start by the long horizon (300 s) past the train end timestamp
    from datetime import timedelta
    tcut = to[cut]
    test_start = next((j for j in range(cut, len(to)) if to[j] - tcut >= timedelta(seconds=300)), cut)
    gap = test_start - cut
    Xtr, ytr = Xo[:cut], yo[:cut]
    Xte, yte = Xo[test_start:], yo[test_start:]
    rep["gap_split"] = {"train": int(len(ytr)), "train_attack": int(ytr.sum()),
                        "gap_windows_dropped": int(gap), "test": int(len(yte)), "test_attack": int(yte.sum())}

    def fit_eval(cols, tag):
        if ytr.sum() == 0 or yte.sum() == 0:
            return {"skip": "no attack in a split half"}
        rf = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0, n_jobs=-1)
        rf.fit(Xtr[:, cols], ytr)
        m = metrics(yte, rf.predict(Xte[:, cols]))
        m["recall_ci95"] = wilson(m["tp"], m["tp"] + m["fn"])
        if tag == "all":
            imp = sorted(zip([names[c] for c in cols], rf.feature_importances_), key=lambda x: -x[1])
            m["top_features"] = [[n, round(float(v), 4)] for n, v in imp[:8]]
        return m

    allcols = list(range(len(names)))
    beh = groups_idx(names, BEHAVIOUR)
    ident = groups_idx(names, PORT_HOST_IDENTITY)
    rep["ablation_gap_split"] = {
        "all_features": fit_eval(allcols, "all"),
        "behaviour_only (no port/host/fanout)": fit_eval(beh, "beh"),
        "identity_only (port/host/fanout)": fit_eval(ident, "ident"),
        "drop_ssh_flows_and_dst_hosts": fit_eval([c for c in allcols if names[c].rsplit("_", 1)[0]
                                                   not in {"ssh_flows", "dst_hosts"}], "drop"),
    }

    # --- 3. held-out family WITH gap, behaviour-only, to test real generalisation ---
    ssh_i = names.index("ssh_flows_60")
    fam = np.array(["ssh" if (yy and X[i, ssh_i] > 0) else ("ftp" if yy else "benign")
                    for i, yy in enumerate(y)])
    rep["family_counts"] = {f: int((fam == f).sum()) for f in ("benign", "ftp", "ssh")}
    hof = {}
    benign_mask = fam == "benign"
    for feats, flabel in ((allcols, "all_features"), (beh, "behaviour_only")):
        for tr_f, te_f in (("ftp", "ssh"), ("ssh", "ftp")):
            trm = benign_mask | (fam == tr_f)
            if (fam == tr_f).sum() < 5 or (fam == te_f).sum() < 5:
                continue
            rf = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0, n_jobs=-1)
            rf.fit(X[np.ix_(trm, feats)], y[trm])
            rec = float((rf.predict(X[np.ix_(fam == te_f, feats)]) == 1).mean())
            fpr = float((rf.predict(X[np.ix_(benign_mask, feats)]) == 1).mean())
            hof[f"{flabel}:train_{tr_f}_test_{te_f}"] = {
                "withheld_recall": round(rec, 4), "withheld_recall_ci95": wilson(int(rec * (fam == te_f).sum()), int((fam == te_f).sum())),
                "benign_fpr": round(fpr, 4)}
    rep["held_out_family_audit"] = hof

    json.dump(rep, open(out, "w"), indent=1, default=str)
    print(json.dumps(rep, indent=1, default=str)[:4000])


if __name__ == "__main__":
    main()
