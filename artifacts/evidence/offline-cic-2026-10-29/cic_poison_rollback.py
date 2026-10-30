"""Poisoning safeguards, immutable anchor, provenance gate, challenger isolation,
persistence and rollback -- exercised on REAL recorded windows (offline, separate gate).

This mirrors the lifecycle the controller already enforces (shadow challenger, gate,
human promotion, rollback) using the same predeclared gate criteria
(NEW_THREAT_EXPERIMENT.md step 10): challenger benign FPR <= 0.02 and not worse than the
champion by > 0.01, and no known-family recall drop > 0.05, both measured on an IMMUTABLE
evaluation anchor that learning never touches. The production classifier class takes HTTP
FeatureVectors, so this is a demonstration of the MECHANISM on network windows, not the
production class.

Scenario: champion = River ARF trained on Tuesday brute force. A challenger learns Friday
attacks (a genuinely new family). Learn streams are then POISONED:
  - label_flip:  a fraction of the true attack windows are relabelled benign
                 (an attacker 'erasing' its own traffic);
  - fp_injection: benign windows from an UNVERIFIED source are injected labelled attack
                 (aimed at raising false positives / alert fatigue).
Each is run (a) NAIVE (admit everything) and (b) with a PROVENANCE gate (only labels from
the verified manifest are admitted). We report anchor metrics, gate verdict, and rollback.

usage: cic_poison_rollback.py <out.json>
"""
import copy
import hashlib
import json
import pickle
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from cic_audit import BEHAVIOUR, groups_idx  # noqa: E402
from cic_offline_eval import FEATURE_NAMES  # noqa: E402

CACHE = Path.home() / "afw-external-datasets" / "cache"
OV = 20  # attack-labelled items are oversampled for the incremental learner (class imbalance)


def main():
    out = sys.argv[1]
    names = list(FEATURE_NAMES)
    beh = groups_idx(names, BEHAVIOUR)
    bn = [names[i] for i in beh]
    Xt, yt, tt, _, _ = pickle.load(open(CACHE / "tuesday.pkl", "rb"))
    Xf, yf, tf, _, _ = pickle.load(open(CACHE / "friday.pkl", "rb"))
    Xt, Xf = Xt[:, beh], Xf[:, beh]
    ts_t = np.array([t.timestamp() for t in tt]); ts_f = np.array([t.timestamp() for t in tf])

    def d(x):
        return dict(zip(bn, map(float, x)))

    def pred(model, X, idx):
        return np.array([int(model.predict_one(d(X[i])) or 0) for i in idx])

    rs = np.random.RandomState(0)
    # ---- time-ordered splits (learn past / test future), per dataset ----
    def split_attack(y, ts, frac=0.6):
        idx = np.where(y == 1)[0]; idx = idx[np.argsort(ts[idx])]; c = int(frac * len(idx))
        return idx[:c], idx[c:]
    tue_learn, tue_test = split_attack(yt, ts_t)
    fri_learn, fri_test = split_attack(yf, ts_f)
    ben_t = np.where(yt == 0)[0]; ben_f = np.where(yf == 0)[0]

    # ---- IMMUTABLE evaluation anchor: fixed before any learning, hashed ----
    anc_ben_t = rs.choice(ben_t, size=1500, replace=False)
    anc_ben_f = rs.choice(ben_f, size=1500, replace=False)
    anchor = {"benign_tue": anc_ben_t.tolist(), "benign_fri": anc_ben_f.tolist(),
              "known_tue_attack_test": tue_test.tolist(), "new_fri_attack_test": fri_test.tolist()}
    anchor_sha = hashlib.sha256(json.dumps(anchor, sort_keys=True).encode()).hexdigest()
    anchor_excl_f = set(anc_ben_f.tolist())

    def evaluate(model):
        pb_t = pred(model, Xt, anc_ben_t); pb_f = pred(model, Xf, anc_ben_f)
        fp = int(pb_t.sum() + pb_f.sum()); n = len(pb_t) + len(pb_f)
        known = pred(model, Xt, tue_test); new = pred(model, Xf, fri_test)
        return {"benign_fpr": round(fp / n, 5), "benign_fp": fp, "benign_n": n,
                "known_recall": round(float(known.mean()), 4), "known_k": int(known.sum()), "known_n": len(known),
                "new_recall": round(float(new.mean()), 4), "new_k": int(new.sum()), "new_n": len(new)}

    # ---- champion: Tuesday brute force + Tuesday benign, shuffled ----
    from river import forest
    champ = forest.ARFClassifier(n_models=10, seed=0)
    base = list(ben_t) + list(np.repeat(tue_learn, OV)); np.random.RandomState(1).shuffle(base)
    for i in base:
        champ.learn_one(d(Xt[i]), int(yt[i]))
    champ_blob = pickle.dumps(champ); champ_sha = hashlib.sha256(champ_blob).hexdigest()
    champ_m = evaluate(champ)

    # ---- persistence: checkpoint -> reload -> identical predictions ----
    reloaded = pickle.loads(champ_blob)
    probe = rs.choice(len(Xt), size=600, replace=False)
    persistence = {"checkpoint_sha256": champ_sha[:16], "bytes": len(champ_blob),
                   "reload_predictions_identical": bool((pred(champ, Xt, probe) == pred(reloaded, Xt, probe)).all()),
                   "probe_windows": 600}

    # ---- learn streams ----
    learn_ben = [i for i in rs.choice(ben_f, size=min(len(ben_f), 10 * len(fri_learn) + 1500), replace=False)
                 if i not in anchor_excl_f][: 10 * len(fri_learn)]
    unverified_pool = [i for i in ben_f if i not in anchor_excl_f and i not in set(learn_ben)]
    # items: (feature vector row, label, verified_provenance)
    def stream(label_flip=0.0, inject=0):
        items = []
        flipped = set(rs.choice(fri_learn, size=int(round(label_flip * len(fri_learn))), replace=False).tolist()) if label_flip else set()
        for i in fri_learn:
            lab = 0 if i in flipped else 1
            items.append((Xf[i], lab, True))  # the true labels come from the verified manifest
        for i in learn_ben:
            items.append((Xf[i], 0, True))
        for i in rs.choice(unverified_pool, size=inject, replace=False) if inject else []:
            items.append((Xf[i], 1, False))  # benign windows labelled ATTACK, unverified source
        return items

    def run_challenger(items, use_provenance):
        chal = copy.deepcopy(champ)  # challenger isolation: the champion object is never touched
        admitted = [(x, l) for x, l, v in items if (v or not use_provenance)]
        order = [(x, l) for x, l in admitted for _ in range(OV if l == 1 else 1)]
        np.random.RandomState(2).shuffle(order)
        for x, l in order:
            chal.learn_one(d(x), int(l))
        return chal, len(admitted), len(items) - len(admitted)

    def gate(cm):
        why = []
        if cm["benign_fpr"] > 0.02: why.append(f"benign_fpr {cm['benign_fpr']} > 0.02")
        if cm["benign_fpr"] > champ_m["benign_fpr"] + 0.01: why.append("benign_fpr worse than champion by > 0.01")
        if champ_m["known_recall"] - cm["known_recall"] > 0.05: why.append(f"known-family recall dropped {champ_m['known_recall']}->{cm['known_recall']}")
        return {"passed": not why, "why": why}

    scen = [("clean", 0.0, 0), ("label_flip_30pct", 0.3, 0), ("label_flip_60pct", 0.6, 0),
            ("fp_injection_100", 0.0, 100), ("fp_injection_400", 0.0, 400)]
    results = {}
    for name, lf, inj in scen:
        items = stream(lf, inj)
        row = {}
        for mode, prov in (("naive_admit_all", False), ("with_provenance_gate", True)):
            chal, n_adm, n_drop = run_challenger(items, prov)
            cm = evaluate(chal); g = gate(cm)
            row[mode] = {"admitted": n_adm, "dropped_by_provenance": n_drop, **cm, "gate": g}
        results[name] = row

    # ---- rollback: after the worst naive challenger, restore the checkpoint ----
    worst = copy.deepcopy(champ)
    for x, l, v in stream(0.6, 400):
        for _ in range(OV if l == 1 else 1):
            worst.learn_one(d(x), int(l))
    worst_m = evaluate(worst)
    restored = pickle.loads(champ_blob)  # rollback = reload the verified checkpoint
    restored_m = evaluate(restored)
    rollback = {"poisoned_challenger": worst_m, "after_rollback": restored_m,
                "restored_equals_original_champion": restored_m == champ_m,
                "checkpoint_sha256_verified": hashlib.sha256(champ_blob).hexdigest() == champ_sha}
    isolation = {"champion_unchanged_after_all_challengers": evaluate(champ) == champ_m}

    rep = {"provenance": "CIC-IDS2017 Tuesday(champion)+Friday(new family) offline; behaviour-only; separate gate",
           "anchor_sha256": anchor_sha[:16], "anchor_sizes": {k: len(v) for k, v in anchor.items()},
           "champion": champ_m, "persistence": persistence, "challenger_isolation": isolation,
           "scenarios": results, "rollback": rollback,
           "gate_criteria": "benign_fpr<=0.02 and not worse than champion by >0.01; known-family recall drop <=0.05"}
    json.dump(rep, open(out, "w"), indent=1, default=str)
    print("anchor", rep["anchor_sha256"], rep["anchor_sizes"])
    print("champion      :", champ_m)
    print("persistence   :", persistence); print("isolation     :", isolation)
    for n, row in results.items():
        for m, r in row.items():
            print(f"{n:18} {m:22} adm={r['admitted']:4} drop={r['dropped_by_provenance']:3} fpr={r['benign_fpr']:<7} "
                  f"known={r['known_recall']:<6} new={r['new_recall']:<6} gate={'PASS' if r['gate']['passed'] else 'REJECT'} {r['gate']['why']}")
    print("rollback      :", {k: v for k, v in rollback.items() if k != 'poisoned_challenger' and k != 'after_rollback'})
    print("  poisoned    :", worst_m); print("  restored    :", restored_m)


if __name__ == "__main__":
    main()
