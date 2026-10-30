"""Self-learning demonstration on recorded attack traffic (P3).

Shows a challenger learning a previously WITHHELD malicious pattern and improving on
UNTOUCHED examples, then checks it does not forget the family it already knew.

Scope/limits (honest): CIC-IDS2017 Tuesday has ONE FTP run and ONE SSH run, so "untouched"
here is a within-run temporal holdout (first 60% of the withheld family = learn, last 40%
= test), not an independent second run. Rigorous independent-run evidence needs more data.
Behaviour-only features (no port/host identity) are used, so the result is not a port
artifact. Separate from any live GNS3 claim.

usage: cic_selflearn.py <eve.json> <out.json>
"""
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cic_offline_eval import FEATURE_NAMES, build  # noqa: E402
from cic_audit import BEHAVIOUR, groups_idx  # noqa: E402


def recall(model, names, X, rows):
    if len(rows) == 0:
        return None
    preds = [int(model.predict_one(dict(zip(names, map(float, X[i])))) or 0) for i in rows]
    return round(float(np.mean(preds)), 4)


def main():
    eve, out = sys.argv[1], sys.argv[2]
    X, y, times, srcs, _ = build(eve)
    names = list(FEATURE_NAMES)
    beh = groups_idx(names, BEHAVIOUR)
    Xb = X[:, beh]
    bnames = [names[i] for i in beh]
    ssh_i = names.index("ssh_flows_60")
    fam = np.array(["ssh" if (yy and X[i, ssh_i] > 0) else ("ftp" if yy else "benign")
                    for i, yy in enumerate(y)])
    t = np.array([tt.timestamp() for tt in times])

    # withheld family = FTP (an SSH-trained model partly misses it). Known family = SSH.
    def tsplit(mask, frac=0.6):
        idx = np.where(mask)[0]
        idx = idx[np.argsort(t[idx])]
        c = int(frac * len(idx))
        return idx[:c], idx[c:]
    ftp_learn, ftp_test = tsplit(fam == "ftp")
    ssh_learn, ssh_test = tsplit(fam == "ssh")
    benign_idx = np.where(fam == "benign")[0]

    from river import forest

    def new():
        return forest.ARFClassifier(n_models=10, seed=0)

    # base challenger: benign + the KNOWN family (SSH). Oversample the rare attack class
    # (~0.5% prevalence) so the incremental ARF actually learns it (the audit showed ARF
    # collapses to the majority without this). Shuffled to avoid the ordering artifact.
    OV = 20
    base_stream = list(benign_idx) + list(np.repeat(ssh_learn, OV))
    np.random.RandomState(0).shuffle(base_stream)
    clf = new()
    for i in base_stream:
        clf.learn_one(dict(zip(bnames, map(float, Xb[i]))), int(y[i]))

    rep = {
        "provenance": "EXTERNAL CIC-IDS2017 offline; within-run temporal holdout; behaviour-only features",
        "counts": {"benign": int(len(benign_idx)), "ftp_learn": int(len(ftp_learn)),
                   "ftp_test(withheld,untouched)": int(len(ftp_test)),
                   "ssh_learn": int(len(ssh_learn)), "ssh_test": int(len(ssh_test))},
        "before_learning_ftp": {
            "withheld_FTP_recall(untouched)": recall(clf, bnames, Xb, ftp_test),
            "known_SSH_recall": recall(clf, bnames, Xb, ssh_test),
        },
    }

    # incremental learning of the withheld family (predict-before-learn), interleaved with
    # benign so it does not just chase the new class
    ftp_set = set(ftp_learn.tolist())
    learn_bg = np.random.RandomState(1).choice(benign_idx, size=min(len(benign_idx), 10 * len(ftp_learn)), replace=False)
    learn_stream = list(np.repeat(ftp_learn, OV)) + list(learn_bg)
    np.random.RandomState(2).shuffle(learn_stream)
    pre_learn_preds, seen = [], set()
    for i in learn_stream:
        d = dict(zip(bnames, map(float, Xb[i])))
        if i in ftp_set and i not in seen:  # predict BEFORE the first time we learn each FTP window
            pre_learn_preds.append(int(clf.predict_one(d) or 0))
            seen.add(i)
        clf.learn_one(d, int(y[i]))

    rep["during_learning"] = {
        "ftp_learn_windows": int(len(ftp_learn)),
        "predicted_attack_before_learning_each (zero-day recall on the learn stream)":
            round(float(np.mean(pre_learn_preds)), 4) if pre_learn_preds else None,
    }
    rep["after_learning_ftp"] = {
        "withheld_FTP_recall(untouched)": recall(clf, bnames, Xb, ftp_test),
        "known_SSH_recall(forgetting_check)": recall(clf, bnames, Xb, ssh_test),
        "benign_fpr(sample)": round(float(np.mean([int(clf.predict_one(dict(zip(bnames, map(float, Xb[i])))) or 0)
                                                   for i in np.random.RandomState(3).choice(benign_idx, size=min(2000, len(benign_idx)), replace=False)])), 4),
    }
    b = rep["before_learning_ftp"]["withheld_FTP_recall(untouched)"]
    a = rep["after_learning_ftp"]["withheld_FTP_recall(untouched)"]
    rep["verdict"] = {
        "ftp_recall_before": b, "ftp_recall_after": a,
        "improved": (a is not None and b is not None and a > b),
        "ssh_retained": rep["after_learning_ftp"]["known_SSH_recall(forgetting_check)"],
        "note": "mechanisms for poisoning-resistant admission, delayed labels, checkpoints "
                "and rollback are in ml/incremental.py (ClassifierLifecycle), unit-tested on "
                "SYNTHETIC data; this demo exercises before/after + forgetting on real data.",
    }
    json.dump(rep, open(out, "w"), indent=1, default=str)
    print(json.dumps(rep, indent=1, default=str)[:3500])


if __name__ == "__main__":
    main()
