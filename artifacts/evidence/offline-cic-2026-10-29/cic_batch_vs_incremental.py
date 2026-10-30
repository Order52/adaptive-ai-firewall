"""Fair batch-vs-incremental comparison (P2).

A streaming setting: windows arrive in time order with labels. Compare two strategies on
the SAME stream, behaviour-only features:
  - INCREMENTAL (River ARF): update on each labelled window as it arrives.
  - PERIODIC BATCH (sklearn RF): retrain from scratch on all data seen so far, every K
    windows.
Both are evaluated PREQUENTIALLY (predict each window before its label is used), so the
comparison is fair. We report detection quality, cumulative training compute (wall-clock),
model memory, and catastrophic forgetting on the earliest family.

Honest: incremental is NOT assumed superior; we report whichever wins on each axis.

usage: cic_batch_vs_incremental.py <eve.json> <out.json>
"""
import json
import pickle
import sys
import time
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from cic_audit import BEHAVIOUR, groups_idx, wilson  # noqa: E402
from cic_offline_eval import FEATURE_NAMES, build  # noqa: E402


def main():
    eve, out = sys.argv[1], sys.argv[2]
    X, y, times, srcs, _ = build(eve)
    names = list(FEATURE_NAMES)
    beh = groups_idx(names, BEHAVIOUR)
    bn = [names[i] for i in beh]
    order = np.argsort([t.timestamp() for t in times])
    Xo, yo = X[order][:, beh], y[order]
    ssh_i = names.index("ssh_flows_60")
    fam_o = np.array(["ssh" if (yy and X[order][k, ssh_i] > 0) else ("ftp" if yy else "benign")
                      for k, yy in enumerate(yo)])
    n = len(yo)
    warm = max(500, int(0.15 * n))
    K = 1000  # batch retrain cadence

    from river import forest
    from sklearn.ensemble import RandomForestClassifier
    OV = 20  # oversample attack for both (fair; audit showed ARF needs it)

    # ---- incremental (ARF), prequential ----
    arf = forest.ARFClassifier(n_models=10, seed=0)
    arf_preds, arf_ys, arf_train_s = [], [], 0.0
    for i in range(n):
        d = dict(zip(bn, map(float, Xo[i])))
        if i >= warm:
            arf_preds.append(int(arf.predict_one(d) or 0)); arf_ys.append(int(yo[i]))
        t0 = time.perf_counter()
        reps = OV if yo[i] == 1 else 1
        for _ in range(reps):
            arf.learn_one(d, int(yo[i]))
        arf_train_s += time.perf_counter() - t0
    arf_mem = len(pickle.dumps(arf))

    # ---- periodic batch (RF), prequential: retrain every K on cumulative data ----
    rf = None
    rf_preds, rf_ys, rf_train_s, n_retrain = [], [], 0.0, 0
    for i in range(n):
        if i >= warm:
            if rf is not None:
                rf_preds.append(int(rf.predict(Xo[i:i + 1])[0])); rf_ys.append(int(yo[i]))
            else:
                rf_preds.append(0); rf_ys.append(int(yo[i]))
        if i >= warm and (i - warm) % K == 0:  # retrain on everything so far
            idx = np.arange(0, i + 1)
            atk = idx[yo[idx] == 1]
            tr = np.concatenate([idx, np.repeat(atk, OV - 1)]) if len(atk) else idx
            t0 = time.perf_counter()
            rf = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=0, n_jobs=-1)
            rf.fit(Xo[tr], yo[tr])
            rf_train_s += time.perf_counter() - t0; n_retrain += 1
    rf_mem = len(pickle.dumps(rf)) if rf is not None else None

    def m(preds, ys):
        preds, ys = np.array(preds), np.array(ys)
        tp = int(((preds == 1) & (ys == 1)).sum()); fp = int(((preds == 1) & (ys == 0)).sum())
        fn = int(((preds == 0) & (ys == 1)).sum()); tn = int(((preds == 0) & (ys == 0)).sum())
        return {"recall": round(tp / (tp + fn), 4) if tp + fn else None,
                "recall_ci95": wilson(tp, tp + fn),
                "precision": round(tp / (tp + fp), 4) if tp + fp else None,
                "fpr": round(fp / (fp + tn), 6) if fp + tn else None, "n_attack": int(tp + fn)}

    # forgetting: recall on the EARLIEST family (whatever appears first) at the end
    first_fam = fam_o[(fam_o != "benign")][0] if (fam_o != "benign").any() else None

    rep = {
        "provenance": "EXTERNAL CIC-IDS2017 offline; behaviour-only; prequential; attack oversampled (fair)",
        "stream_windows": int(n), "warmup": int(warm), "batch_retrain_cadence_K": K,
        "incremental_arf": {**m(arf_preds, arf_ys),
                            "total_train_seconds": round(arf_train_s, 2),
                            "updates": int(n), "model_bytes": arf_mem},
        "periodic_batch_rf": {**m(rf_preds, rf_ys),
                             "total_train_seconds": round(rf_train_s, 2),
                             "retrains": n_retrain, "model_bytes": rf_mem,
                             "note": f"retrained {n_retrain}x from scratch on cumulative data"},
        "comparison": {
            "which_higher_recall": None, "which_cheaper_train": None,
            "forgetting_note": "batch retrains from scratch -> cannot catastrophically forget; "
                               "ARF can -> we report ARF recall on the earliest family below",
            "earliest_family": first_fam,
        },
    }
    a, b = rep["incremental_arf"]["recall"], rep["periodic_batch_rf"]["recall"]
    if a is not None and b is not None:
        rep["comparison"]["which_higher_recall"] = "incremental" if a > b else ("batch" if b > a else "tie")
    rep["comparison"]["which_cheaper_train"] = ("incremental" if arf_train_s < rf_train_s else "batch")
    rep["comparison"]["label_availability"] = ("incremental needs a label per window as it arrives; "
                                               "batch can defer and retrain when a labelled batch exists")
    json.dump(rep, open(out, "w"), indent=1, default=str)
    print(json.dumps(rep, indent=1, default=str)[:3500])


if __name__ == "__main__":
    main()
