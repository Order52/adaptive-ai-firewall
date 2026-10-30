"""Third independent capture: CIC-IDS2017 Thursday (web attacks + infiltration). Offline,
separate gate. Behaviour-only features, run-level uncertainty, properly held-out anchors.

Different from Tuesday (FTP/SSH brute force) and Friday (port scan / botnet / DDoS): Thursday
is HTTP-layer attacker activity (web brute force, XSS, SQL injection) from different tooling,
plus an infiltration phase.

  1. cross-dataset:  RF trained on Tuesday+Friday -> Thursday (does it transfer?)
  2. within-Thursday: time split with a 300 s gap
  3. static Suricata (ET Open) vs ML on the same Thursday windows
  4. third-family self-learning, 10 seeds, immutable held-out anchors:
        old families = Tuesday brute force + Friday attacks, new family = Thursday,
        strategies: incremental (no rehearsal) / incremental + rehearsal / periodic batch RF

Labels are by ATTACKER IP (THU_ATTACKERS env, default the Kali host + its NAT address); the
label audit in the evidence folder justifies the choice.  Windows from other sources
(including any compromised internal hosts) are labelled benign, which UNDERSTATES recall.

usage: cic_thursday_eval.py <thursday_rules_eve.json> <out.json>
"""
import copy
import json
import os
import pickle
import sys
import time
from datetime import timedelta
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
EVD = HERE.parent / "offline-cic-2026-10-29"
sys.path.insert(0, str(EVD))
from cic_audit import BEHAVIOUR, groups_idx, wilson  # noqa: E402
from cic_offline_eval import FEATURE_NAMES  # noqa: E402
from cic_robustness import block_bootstrap, bursts, cached_build, metrics  # noqa: E402
from cic_static_vs_ml import load_alerts  # noqa: E402

CACHE = Path.home() / "afw-external-datasets" / "cache"
OV = 20
SEEDS = list(range(10))
ATT = set(os.environ.get("THU_ATTACKERS", "172.16.0.1,205.174.165.73,205.174.165.80").split(","))
EXC = set(os.environ.get("THU_EXCLUDE", "192.168.10.8,192.168.10.25").split(","))


def summarise(y, p, ts):
    tp, fn, fp, tn = metrics(y, p)
    r = {"recall": round(tp / (tp + fn), 4) if tp + fn else None, "tp": tp, "fn": fn, "fp": fp, "tn": tn,
         "fpr": round(fp / (fp + tn), 6) if fp + tn else None,
         "recall_ci95_wilson": wilson(tp, tp + fn), "independent_attack_bursts": bursts(ts, y)}
    r.update(block_bootstrap(y, p, ts))
    return r


def main():
    eve, out = sys.argv[1], sys.argv[2]
    names = list(FEATURE_NAMES)
    beh = groups_idx(names, BEHAVIOUR)
    bn = [names[i] for i in beh]

    X, y, times, srcs, _ = cached_build(eve, "thursday")
    y = np.array([int(s in ATT) for s in srcs])  # relabel by the audited attacker set
    ts = np.array([t.timestamp() for t in times])
    o = np.argsort(ts); X, y, ts = X[o], y[o], ts[o]
    srcs = [srcs[i] for i in o]; times = [times[i] for i in o]
    # Compromised internal hosts (UNB: infiltration victims 192.168.10.8 Win Vista -- which then
    # runs an Nmap sweep -- and 192.168.10.25 Mac) emit a MIX of benign and attack traffic that an
    # IP label cannot separate. They are EXCLUDED (neither benign nor attack): counting them
    # benign would punish correct detections, counting them attack would be a guess.
    keep = np.array([s not in EXC for s in srcs])
    n_excl = int((~keep).sum())
    X, y, ts = X[keep], y[keep], ts[keep]
    srcs = [s for s, k in zip(srcs, keep) if k]; times = [t for t, k in zip(times, keep) if k]
    Xb = X[:, beh]
    Xt, yt, tt_, _, _ = pickle.load(open(CACHE / "tuesday.pkl", "rb"))
    Xf, yf, tf_, _, _ = pickle.load(open(CACHE / "friday.pkl", "rb"))
    Xt, Xf = Xt[:, beh], Xf[:, beh]
    ts_t = np.array([t.timestamp() for t in tt_]); ts_f = np.array([t.timestamp() for t in tf_])

    rep = {"provenance": "CIC-IDS2017 Thursday offline; behaviour-only; separate gate",
           "attackers_labelled": sorted(ATT), "excluded_compromised_hosts": sorted(EXC),
           "excluded_windows": n_excl, "windows": int(len(y)), "attack_windows": int(y.sum()),
           "independent_attack_bursts": bursts(ts, y)}
    from sklearn.ensemble import RandomForestClassifier

    def rf(seed=0, n=300):
        return RandomForestClassifier(n_estimators=n, class_weight="balanced", random_state=seed, n_jobs=-1)

    # ---- 1. cross-dataset: Tuesday+Friday -> Thursday ----
    clf = rf().fit(np.vstack([Xt, Xf]), np.concatenate([yt, yf]))
    rep["cross_dataset_tue_fri_to_thu"] = summarise(y, clf.predict(Xb), ts)

    # ---- 2. within-Thursday, 300 s gap ----
    cut = int(0.6 * len(y))
    start = next((j for j in range(cut, len(y)) if ts[j] - ts[cut] >= 300), cut)
    if y[:cut].sum() and y[start:].sum():
        c2 = rf().fit(Xb[:cut], y[:cut])
        rep["within_thursday"] = summarise(y[start:], c2.predict(Xb[start:]), ts[start:])
        rep["within_thursday"]["split"] = {"train": int(cut), "gap": int(start - cut), "test": int(len(y) - start)}
        p_ml_te = c2.predict(Xb[start:])
    else:
        rep["within_thursday"] = {"skip": "attack missing from a split half"}
        p_ml_te = None

    # ---- 3. static Suricata (ET Open) vs ML on the same test windows ----
    alerts, alerted, attack_cat = load_alerts(os.environ.get("RULES_EVE", str(Path.home() / "afw-external-datasets/cic-ids2017/Thursday-fair-out/eve.json")))
    def hit(i, atk_only):
        a = alerts.get(srcs[i])
        if not a:
            return 0
        lo = times[i] - timedelta(seconds=60)
        return int(any(lo <= t <= times[i] and (m or not atk_only) for t, m in a))
    sur_atk = np.array([hit(i, True) for i in range(len(y))]); sur_all = np.array([hit(i, False) for i in range(len(y))])
    te = slice(start, len(y))
    rep["static_vs_ml_test_split"] = {
        "suricata_alert_noise": {"distinct_sources_alerted": len(alerted), "distinct_sources_attack_category": len(attack_cat),
                                 "attacker_triggers_attack_category_rule": any(a in attack_cat for a in ATT)},
        "static_suricata_all_alerts": summarise(y[te], sur_all[te], ts[te]),
        "static_suricata_attack_category": summarise(y[te], sur_atk[te], ts[te])}
    if p_ml_te is not None:
        rep["static_vs_ml_test_split"]["supervised_ml"] = summarise(y[te], p_ml_te, ts[te])
        rep["static_vs_ml_test_split"]["ml_catches_static_misses"] = int(((p_ml_te == 1) & (sur_atk[te] == 0) & (y[te] == 1)).sum())
        rep["static_vs_ml_test_split"]["static_catches_ml_misses"] = int(((sur_atk[te] == 1) & (p_ml_te == 0) & (y[te] == 1)).sum())

    # ---- 4. third-family self-learning (10 seeds) ----
    def split_attack(yv, tv, frac=0.6):
        idx = np.where(yv == 1)[0]; idx = idx[np.argsort(tv[idx])]; c = int(frac * len(idx)); return idx[:c], idx[c:]
    tue_l, tue_t = split_attack(yt, ts_t); fri_l, fri_t = split_attack(yf, ts_f); thu_l, thu_t = split_attack(y, ts)
    ben_t, ben_f, ben_h = np.where(yt == 0)[0], np.where(yf == 0)[0], np.where(y == 0)[0]
    rs = np.random.RandomState(0)
    a_t, a_f, a_h = rs.choice(ben_t, 1000, replace=False), rs.choice(ben_f, 1000, replace=False), rs.choice(ben_h, 1000, replace=False)
    excl_h = set(a_h.tolist())
    learn_ben_h = [i for i in rs.choice(ben_h, size=min(len(ben_h), 10 * len(thu_l) + 1500), replace=False) if i not in excl_h][: 10 * max(1, len(thu_l))]
    d = lambda x: dict(zip(bn, map(float, x)))  # noqa: E731
    P = lambda m, M, idx: np.array([int(m.predict_one(d(M[i])) or 0) for i in idx])  # noqa: E731
    R = lambda m, M, idx: np.array(m.predict(M[idx]))  # noqa: E731

    def ev(pred_fn):
        b = np.concatenate([pred_fn(Xt, a_t), pred_fn(Xf, a_f), pred_fn(Xb, a_h)])
        return {"benign_fpr": float(b.mean()), "old_tue_recall": float(pred_fn(Xt, tue_t).mean()),
                "old_fri_recall": float(pred_fn(Xf, fri_t).mean()), "new_thu_recall": float(pred_fn(Xb, thu_t).mean())}
    if len(thu_l) >= 5 and len(thu_t) >= 5 and len(tue_t) and len(fri_t):
        from river import forest
        runs = {k: [] for k in ("champion", "incremental_no_rehearsal", "incremental_with_rehearsal", "periodic_batch_rf")}
        cost = {k: [] for k in ("incremental_no_rehearsal", "incremental_with_rehearsal", "periodic_batch_rf")}
        for s in SEEDS:
            r = np.random.RandomState(100 + s)
            champ = forest.ARFClassifier(n_models=10, seed=s)
            base = [(Xt[i], int(yt[i])) for i in ben_t] + [(Xt[i], 1) for i in tue_l for _ in range(OV)] \
                 + [(Xf[i], 0) for i in ben_f] + [(Xf[i], 1) for i in fri_l for _ in range(OV)]
            r.shuffle(base)
            for x, l in base:
                champ.learn_one(d(x), l)
            runs["champion"].append(ev(lambda M, idx, m=champ: P(m, M, idx)))
            new_items = [(Xb[i], 1) for i in thu_l for _ in range(OV)] + [(Xb[i], 0) for i in learn_ben_h]
            a = copy.deepcopy(champ); it = list(new_items); r.shuffle(it); t0 = time.perf_counter()
            for x, l in it: a.learn_one(d(x), l)
            cost["incremental_no_rehearsal"].append(time.perf_counter() - t0)
            runs["incremental_no_rehearsal"].append(ev(lambda M, idx, m=a: P(m, M, idx)))
            b = copy.deepcopy(champ)
            replay = [(Xt[i], 1) for i in tue_l for _ in range(OV)] + [(Xf[i], 1) for i in fri_l for _ in range(OV)] \
                   + [(Xt[i], 0) for i in r.choice(ben_t, 300, replace=False)] + [(Xf[i], 0) for i in r.choice(ben_f, 300, replace=False)]
            it = list(new_items) + replay; r.shuffle(it); t0 = time.perf_counter()
            for x, l in it: b.learn_one(d(x), l)
            cost["incremental_with_rehearsal"].append(time.perf_counter() - t0)
            runs["incremental_with_rehearsal"].append(ev(lambda M, idx, m=b: P(m, M, idx)))
            Xall = np.vstack([Xt[ben_t], Xt[tue_l], Xf[ben_f], Xf[fri_l], Xb[thu_l], Xb[learn_ben_h]])
            yall = np.concatenate([np.zeros(len(ben_t)), np.ones(len(tue_l)), np.zeros(len(ben_f)), np.ones(len(fri_l)),
                                   np.ones(len(thu_l)), np.zeros(len(learn_ben_h))])
            t0 = time.perf_counter(); m3 = rf(s, 100).fit(Xall, yall); cost["periodic_batch_rf"].append(time.perf_counter() - t0)
            runs["periodic_batch_rf"].append(ev(lambda M, idx, m=m3: R(m, M, idx)))
            print(f"third-family seed {s} done", flush=True)
        def agg(rows):
            res = {}
            for k in rows[0]:
                v = np.array([q[k] for q in rows]); res[k] = {"mean": round(float(v.mean()), 4), "sd": round(float(v.std(ddof=1)), 4),
                                                              "min": round(float(v.min()), 4), "max": round(float(v.max()), 4)}
            return res
        rep["third_family_self_learning"] = {
            "anchor": {"benign": 3000, "old_tue_heldout": int(len(tue_t)), "old_fri_heldout": int(len(fri_t)), "new_thu_heldout": int(len(thu_t))},
            "seeds": len(SEEDS), "summary": {k: agg(v) for k, v in runs.items()},
            "train_seconds_mean": {k: round(float(np.mean(v)), 3) for k, v in cost.items()}}
    else:
        rep["third_family_self_learning"] = {"skip": f"too few held-out windows (thu_learn={len(thu_l)}, thu_test={len(thu_t)})"}

    json.dump(rep, open(out, "w"), indent=1, default=str)
    brief = {k: v for k, v in rep.items() if k != "third_family_self_learning"}
    print(json.dumps(brief, indent=1, default=str)[:3800])
    tf = rep["third_family_self_learning"]
    if "summary" in tf:
        print("\nthird-family (10 seeds, mean ± sd):", tf["anchor"])
        for k, v in tf["summary"].items():
            print(f"  {k:28} FPR={v['benign_fpr']['mean']:.4f}  old-tue={v['old_tue_recall']['mean']:.3f}±{v['old_tue_recall']['sd']:.3f}  "
                  f"old-fri={v['old_fri_recall']['mean']:.3f}±{v['old_fri_recall']['sd']:.3f}  new-thu={v['new_thu_recall']['mean']:.3f}±{v['new_thu_recall']['sd']:.3f}")
        print("  train seconds:", tf["train_seconds_mean"])
    else:
        print("\nthird-family:", tf)


if __name__ == "__main__":
    main()
