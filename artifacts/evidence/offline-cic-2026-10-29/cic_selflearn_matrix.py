"""Rigorous self-learning reproduction across multiple withheld families (P5).

Reproduces the 0->0.625 result with EXACT denominators, Wilson 95% CIs, provenance, and
forgetting measurements, and tests whether comparable improvement appears for OTHER
withheld families (Tuesday FTP, Tuesday SSH, Friday attacks).

Protocol for each withheld family F:
  - base challenger = benign + all OTHER attack families (attack oversampled, shuffled to
    avoid the ordering artifact), behaviour-only features;
  - BEFORE: recall on F's time-held-out test split (model never saw F);
  - learn F's learn split incrementally (predict-before-learn), interleaved with benign;
  - AFTER: recall on F's UNTOUCHED test split; plus recall on the KNOWN families
    (forgetting) and benign FPR.
All denominators and CIs reported. Separate offline gate.

usage: cic_selflearn_matrix.py <tuesday_eve> <friday_eve> <out.json>
"""
import json
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from cic_audit import BEHAVIOUR, groups_idx, wilson  # noqa: E402
from cic_offline_eval import FEATURE_NAMES, build  # noqa: E402


def main():
    tue, fri, out = sys.argv[1], sys.argv[2], sys.argv[3]
    names = list(FEATURE_NAMES)
    beh = groups_idx(names, BEHAVIOUR)
    bn = [names[i] for i in beh]
    ssh_i = names.index("ssh_flows_60")

    Xt, yt, tt, st, _ = build(tue)
    Xf, yf, tf, sf, _ = build(fri)
    famt = np.array(["tue_ssh" if (yy and Xt[i, ssh_i] > 0) else ("tue_ftp" if yy else "benign")
                     for i, yy in enumerate(yt)])
    famf = np.array(["fri_attack" if yy else "benign" for yy in yf])

    # unified arrays (behaviour-only)
    Xb = np.vstack([Xt[:, beh], Xf[:, beh]])
    fam = np.concatenate([famt, famf])
    times = list(tt) + list(tf)
    ts = np.array([t.timestamp() for t in times])

    from river import forest
    OV = 20
    attack_fams = ["tue_ftp", "tue_ssh", "fri_attack"]
    benign_idx = np.where(fam == "benign")[0]

    def tsplit(mask):
        idx = np.where(mask)[0]
        idx = idx[np.argsort(ts[idx])]
        c = int(0.6 * len(idx))
        return idx[:c], idx[c:]

    def recall_ci(model, idx):
        if len(idx) == 0:
            return {"recall": None, "n": 0, "ci95": [None, None]}
        preds = [int(model.predict_one(dict(zip(bn, map(float, Xb[i])))) or 0) for i in idx]
        k = int(np.sum(preds))
        return {"recall": round(k / len(idx), 4), "k": k, "n": int(len(idx)), "ci95": wilson(k, len(idx))}

    rep = {"provenance": "CIC-IDS2017 Tuesday+Friday offline; behaviour-only; attack oversampled; shuffled base",
           "family_counts": {f: int((fam == f).sum()) for f in set(fam)}, "withheld_experiments": {}}

    for F in attack_fams:
        if (fam == F).sum() < 10:
            rep["withheld_experiments"][F] = {"skip": "fewer than 10 windows"}
            continue
        learn, test = tsplit(fam == F)
        others = [g for g in attack_fams if g != F]
        other_idx = np.concatenate([np.where(fam == g)[0] for g in others]) if others else np.array([], dtype=int)
        # base model: benign + OTHER attack families (oversampled), shuffled
        base = list(benign_idx) + list(np.repeat(other_idx, OV))
        np.random.RandomState(0).shuffle(base)
        arf = forest.ARFClassifier(n_models=10, seed=0)
        for i in base:
            arf.learn_one(dict(zip(bn, map(float, Xb[i]))), 1 if fam[i] != "benign" else 0)
        before_F = recall_ci(arf, test)
        before_known = {g: recall_ci(arf, np.where(fam == g)[0]) for g in others}
        # learn F (oversampled, interleaved benign), predict-before-learn
        fset = set(learn.tolist())
        lb = np.random.RandomState(1).choice(benign_idx, size=min(len(benign_idx), 10 * len(learn)), replace=False)
        stream = list(np.repeat(learn, OV)) + list(lb)
        np.random.RandomState(2).shuffle(stream)
        seen = set(); preseq = []
        for i in stream:
            d = dict(zip(bn, map(float, Xb[i])))
            if i in fset and i not in seen:
                preseq.append(int(arf.predict_one(d) or 0)); seen.add(i)
            arf.learn_one(d, 1 if fam[i] != "benign" else 0)
        after_F = recall_ci(arf, test)
        after_known = {g: recall_ci(arf, np.where(fam == g)[0]) for g in others}
        bsamp = np.random.RandomState(3).choice(benign_idx, size=min(3000, len(benign_idx)), replace=False)
        bfpr = round(float(np.mean([int(arf.predict_one(dict(zip(bn, map(float, Xb[i])))) or 0) for i in bsamp])), 5)
        rep["withheld_experiments"][F] = {
            "learn_windows": int(len(learn)), "test_windows(untouched)": int(len(test)),
            "withheld_recall_before": before_F, "withheld_recall_after": after_F,
            "improved": (after_F["recall"] or 0) > (before_F["recall"] or 0),
            "known_families_recall_before": before_known, "known_families_recall_after": after_known,
            "benign_fpr_after(sample)": bfpr,
            "zero_day_on_learn_stream(predict-before-learn)": round(float(np.mean(preseq)), 4) if preseq else None,
        }
    # headline summary
    rep["summary"] = {F: {"before": e.get("withheld_recall_before", {}).get("recall"),
                          "after": e.get("withheld_recall_after", {}).get("recall"),
                          "n_test": e.get("test_windows(untouched)")}
                      for F, e in rep["withheld_experiments"].items() if "skip" not in e}
    json.dump(rep, open(out, "w"), indent=1, default=str)
    print(json.dumps(rep, indent=1, default=str)[:3800])


if __name__ == "__main__":
    main()
