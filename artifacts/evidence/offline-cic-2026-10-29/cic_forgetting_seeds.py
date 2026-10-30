"""Forgetting, measured properly: HELD-OUT known-family recall, many seeds (offline).

Corrects an earlier flaw. Earlier "no forgetting" numbers measured retention on windows the
base model had already TRAINED on (memorisation), from a single seed. Here:
  - the known family (Tuesday brute force) is split in time: learn (past) / test (future);
    retention is measured ONLY on the held-out future part, on an immutable anchor;
  - the new family (Friday attacks) is likewise held out for its recall;
  - 10 seeds (stream order + ARF seed) -> mean / sd / min / max;
  - three strategies on IDENTICAL data and anchors:
      incremental ARF (no rehearsal)  - learns the new family on its own
      incremental ARF + REHEARSAL     - new-family stream interleaved with replayed old-family windows
      periodic batch RF retrain       - refit from scratch on everything seen (cost + memory reported)

usage: cic_forgetting_seeds.py <out.json>
"""
import copy
import json
import pickle
import sys
import time
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from cic_audit import BEHAVIOUR, groups_idx  # noqa: E402
from cic_offline_eval import FEATURE_NAMES  # noqa: E402

CACHE = Path.home() / "afw-external-datasets" / "cache"
OV = 20
SEEDS = list(range(10))


def main():
    out = sys.argv[1]
    names = list(FEATURE_NAMES)
    beh = groups_idx(names, BEHAVIOUR)
    bn = [names[i] for i in beh]
    Xt, yt, tt, _, _ = pickle.load(open(CACHE / "tuesday.pkl", "rb"))
    Xf, yf, tf, _, _ = pickle.load(open(CACHE / "friday.pkl", "rb"))
    Xt, Xf = Xt[:, beh], Xf[:, beh]
    ts_t = np.array([t.timestamp() for t in tt]); ts_f = np.array([t.timestamp() for t in tf])

    def split_attack(y, ts, frac=0.6):
        idx = np.where(y == 1)[0]; idx = idx[np.argsort(ts[idx])]; c = int(frac * len(idx))
        return idx[:c], idx[c:]
    tue_learn, tue_test = split_attack(yt, ts_t)
    fri_learn, fri_test = split_attack(yf, ts_f)
    ben_t = np.where(yt == 0)[0]; ben_f = np.where(yf == 0)[0]
    rs = np.random.RandomState(0)  # same anchor construction as cic_poison_rollback.py
    anc_t = rs.choice(ben_t, size=1500, replace=False); anc_f = rs.choice(ben_f, size=1500, replace=False)
    excl = set(anc_f.tolist())
    learn_ben_f = [i for i in rs.choice(ben_f, size=min(len(ben_f), 10 * len(fri_learn) + 1500), replace=False)
                   if i not in excl][: 10 * len(fri_learn)]

    def d(x):
        return dict(zip(bn, map(float, x)))

    def ev_arf(m):
        pb = np.concatenate([[int(m.predict_one(d(Xt[i])) or 0) for i in anc_t],
                             [int(m.predict_one(d(Xf[i])) or 0) for i in anc_f]])
        k = np.array([int(m.predict_one(d(Xt[i])) or 0) for i in tue_test])
        n = np.array([int(m.predict_one(d(Xf[i])) or 0) for i in fri_test])
        return {"benign_fpr": float(pb.mean()), "known_recall_heldout": float(k.mean()), "new_recall_heldout": float(n.mean())}

    def ev_rf(m):
        pb = np.concatenate([m.predict(Xt[anc_t]), m.predict(Xf[anc_f])])
        return {"benign_fpr": float(pb.mean()),
                "known_recall_heldout": float(m.predict(Xt[tue_test]).mean()),
                "new_recall_heldout": float(m.predict(Xf[fri_test]).mean())}

    from river import forest
    from sklearn.ensemble import RandomForestClassifier

    runs = {"champion": [], "incremental_no_rehearsal": [], "incremental_with_rehearsal": [], "periodic_batch_rf": []}
    cost = {"incremental_no_rehearsal": [], "incremental_with_rehearsal": [], "periodic_batch_rf": []}
    mem = {}
    for s in SEEDS:
        t0 = time.time()
        r = np.random.RandomState(100 + s)
        champ = forest.ARFClassifier(n_models=10, seed=s)
        base = list(ben_t) + list(np.repeat(tue_learn, OV)); r.shuffle(base)
        for i in base:
            champ.learn_one(d(Xt[i]), int(yt[i]))
        runs["champion"].append(ev_arf(champ))

        new_items = [(Xf[i], 1) for i in fri_learn for _ in range(OV)] + [(Xf[i], 0) for i in learn_ben_f]
        # (a) no rehearsal
        a = copy.deepcopy(champ); items = list(new_items); r.shuffle(items)
        c0 = time.perf_counter()
        for x, l in items:
            a.learn_one(d(x), l)
        cost["incremental_no_rehearsal"].append(time.perf_counter() - c0)
        runs["incremental_no_rehearsal"].append(ev_arf(a))
        # (b) with rehearsal: replay the OLD family (learn split) + old benign alongside the new stream
        b = copy.deepcopy(champ)
        replay = [(Xt[i], 1) for i in tue_learn for _ in range(OV)] + [(Xt[i], 0) for i in r.choice(ben_t, size=len(learn_ben_f), replace=False)]
        items = list(new_items) + replay; r.shuffle(items)
        c0 = time.perf_counter()
        for x, l in items:
            b.learn_one(d(x), l)
        cost["incremental_with_rehearsal"].append(time.perf_counter() - c0)
        runs["incremental_with_rehearsal"].append(ev_arf(b))
        # (c) periodic batch RF: refit from scratch on everything seen
        Xall = np.vstack([Xt[ben_t], Xt[tue_learn], Xf[fri_learn], Xf[learn_ben_f]])
        yall = np.concatenate([np.zeros(len(ben_t)), np.ones(len(tue_learn)), np.ones(len(fri_learn)), np.zeros(len(learn_ben_f))])
        c0 = time.perf_counter()
        rf = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=s, n_jobs=-1).fit(Xall, yall)
        cost["periodic_batch_rf"].append(time.perf_counter() - c0)
        runs["periodic_batch_rf"].append(ev_rf(rf))
        if s == 0:
            mem = {"incremental_arf_bytes": len(pickle.dumps(b)), "batch_rf_bytes": len(pickle.dumps(rf))}
        print(f"seed {s} done in {time.time()-t0:.0f}s", flush=True)

    def agg(rows):
        o = {}
        for k in ("benign_fpr", "known_recall_heldout", "new_recall_heldout"):
            v = np.array([r_[k] for r_ in rows])
            o[k] = {"mean": round(float(v.mean()), 4), "sd": round(float(v.std(ddof=1)), 4),
                    "min": round(float(v.min()), 4), "max": round(float(v.max()), 4)}
        return o
    rep = {"provenance": "CIC Tuesday(known)+Friday(new) offline; behaviour-only; held-out anchors; 10 seeds",
           "anchor": {"benign": 3000, "known_heldout_attack": int(len(tue_test)), "new_heldout_attack": int(len(fri_test))},
           "seeds": len(SEEDS), "memory_bytes": mem,
           "summary": {k: agg(v) for k, v in runs.items()},
           "train_seconds_mean": {k: round(float(np.mean(v)), 3) for k, v in cost.items()},
           "per_seed": runs}
    json.dump(rep, open(out, "w"), indent=1, default=str)
    print(f"\nanchor: benign=3000 known_heldout={len(tue_test)} new_heldout={len(fri_test)} | seeds={len(SEEDS)}")
    print(f"{'strategy':28} {'benign FPR':>16} {'known recall (held-out)':>26} {'new recall (held-out)':>24}")
    for k, v in rep["summary"].items():
        f = lambda m: f"{m['mean']:.3f}±{m['sd']:.3f} [{m['min']:.2f},{m['max']:.2f}]"  # noqa: E731
        print(f"{k:28} {f(v['benign_fpr']):>16} {f(v['known_recall_heldout']):>26} {f(v['new_recall_heldout']):>24}")
    print("train seconds (mean):", rep["train_seconds_mean"], "| memory:", mem)


if __name__ == "__main__":
    main()
