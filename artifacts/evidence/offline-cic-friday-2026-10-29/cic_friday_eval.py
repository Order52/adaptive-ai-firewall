"""Independent-run / cross-family evaluation on CIC-IDS2017 Friday (P1).

Tests generalisation of the Tuesday brute-force findings to a GENUINELY INDEPENDENT
capture: a different day, different attack families (PortScan / DDoS / Botnet), different
attacker sessions. Answers the question "is the Tuesday result dataset/tool/family
specific?".

Three experiments (behaviour-only features throughout, to avoid the port/host-identity
and tool-id shortcuts the Tuesday audit flagged):
  1. Cross-dataset generalisation: a model TRAINED ON TUESDAY brute force, tested on
     Friday attacks (expect LOW if the model is family-specific — the honest hypothesis).
  2. Our NetworkNovelty detector (fixed scan ceilings, ADR-042) on real recorded
     PortScan — does the scan-detection DESIGN fire on real NMAP scans?
  3. Self-learning with an independent withheld family: Tuesday-brute-force model learns
     Friday PortScan; before/after recall on UNTOUCHED held-out PortScan + forgetting
     check on Tuesday brute force.

usage: cic_friday_eval.py <friday_eve.json> <tuesday_eve.json> <out.json>
"""
import json
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "offline-cic-2026-10-29"))
from cic_offline_eval import FEATURE_NAMES, build  # noqa: E402
from cic_audit import BEHAVIOUR, groups_idx, wilson  # noqa: E402
from cic_offline_eval import metrics  # noqa: E402


def main():
    fri_eve, tue_eve, out = sys.argv[1], sys.argv[2], sys.argv[3]
    names = list(FEATURE_NAMES)
    beh = groups_idx(names, BEHAVIOUR)

    Xf, yf, tf, sf, nf = build(fri_eve)
    Xt, yt, tt, st, nt = build(tue_eve)
    rep = {
        "provenance": "EXTERNAL CIC-IDS2017 Friday (independent day/families) vs Tuesday; behaviour-only",
        "friday": {"windows": int(len(yf)), "attack": int(yf.sum()), "benign": int((yf == 0).sum()),
                   "attacker_sources": sorted({s for s, a in zip(sf, yf) if a})},
        "tuesday": {"windows": int(len(yt)), "attack": int(yt.sum())},
    }
    # describe the Friday attacker's behaviour (what family?) via the scan-shaped features
    for key in ("dst_ports_60", "max_ports_per_host_60", "flows_60", "failed_60",
                "dst_hosts_60", "bytes_out_log_60", "sweep_hosts_60"):
        if key in names:
            i = names.index(key)
            a = Xf[yf == 1, i]
            if len(a):
                rep.setdefault("friday_attacker_features", {})[key] = {
                    "median": round(float(np.median(a)), 2), "p90": round(float(np.quantile(a, 0.9)), 2),
                    "max": round(float(a.max()), 2)}

    from sklearn.ensemble import RandomForestClassifier

    def rf():
        return RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0, n_jobs=-1)

    # --- 1. cross-dataset: Tuesday-trained -> Friday attacks ---
    if yt.sum() and yf.sum():
        clf = rf(); clf.fit(Xt[:, beh], yt)
        pred_f = clf.predict(Xf[:, beh])
        m = metrics(yf, pred_f)
        m["recall_ci95"] = wilson(m["tp"], m["tp"] + m["fn"])
        m["interpretation"] = ("high => Tuesday brute-force behaviour generalises to Friday families; "
                               "low => the model is family-specific (expected/honest)")
        rep["cross_dataset_tuesday_to_friday"] = m

    # --- within-Friday supervised: can the pipeline detect Friday attacks when TRAINED
    #     on Friday? (train first 60% by time, test last 40%) ---
    if yf.sum():
        of = np.argsort([t.timestamp() for t in tf])
        Xfo, yfo = Xf[of][:, beh], yf[of]
        cf = int(0.6 * len(yfo))
        if yfo[:cf].sum() and yfo[cf:].sum():
            clf2 = rf(); clf2.fit(Xfo[:cf], yfo[:cf])
            mm = metrics(yfo[cf:], clf2.predict(Xfo[cf:]))
            mm["recall_ci95"] = wilson(mm["tp"], mm["tp"] + mm["fn"])
            rep["within_friday_supervised"] = mm

    # --- NetworkNovelty (fixed scan ceilings, ADR-042) on the real slow PortScan ---
    dp = names.index("dst_ports_60")
    scan_hi = (yf == 1) & (Xf[:, dp] >= 15)
    try:
        from ipaddress import IPv4Address

        from afw.features.network import NetworkVector as NV
        from afw.ml.network_detector import NetworkNovelty
        det = NetworkNovelty()  # ceilings only = the shipped scan detector

        def wrap(x):
            return NV(source_ip=IPv4Address("0.0.0.0"), window_end=tf[0],
                      values=dict(zip(FEATURE_NAMES, map(float, x))), n_events=1)
        atk_f = Xf[yf == 1]
        strong = np.array([det.assess(wrap(x)).strong for x in atk_f])
        benign_sample = Xf[yf == 0][np.random.RandomState(0).choice(int((yf == 0).sum()), size=min(3000, int((yf == 0).sum())), replace=False)]
        fs = np.array([det.assess(wrap(x)).strong for x in benign_sample])
        rep["network_novelty_scan_ceiling_on_friday"] = {
            "friday_attack_windows": int((yf == 1).sum()),
            "windows_hitting_15port_ceiling": int(scan_hi.sum()),
            "attack_windows_flagged_strong": round(float(strong.mean()), 4),
            "benign_false_strong_rate": round(float(fs.mean()), 5),
            "finding": "the 997-port NMAP scan is SPREAD OUT, so few windows reach the fixed "
                       "15-ports/60s ceiling -> the ceiling-based scan detector MISSES most of "
                       "a slow scan (a real limitation; see RESULTS)."}
    except Exception as e:
        rep["network_novelty_scan_ceiling_on_friday"] = {"error": str(e)[:300]}

    # --- self-learning: Tuesday brute force -> withheld FRIDAY attacks (independent family) ---
    try:
        from river import forest
        scan_idx = np.where(yf == 1)[0]  # all Friday attacks (portscan+ddos+botnet)
        scan_idx = scan_idx[np.argsort([tf[i].timestamp() for i in scan_idx])]
        c = int(0.6 * len(scan_idx))
        ps_learn, ps_test = scan_idx[:c], scan_idx[c:]
        # base model = Tuesday brute force + Tuesday benign, attack oversampled, shuffled
        OV = 20
        atk_t = np.where(yt == 1)[0]
        base = list(np.where(yt == 0)[0]) + list(np.repeat(atk_t, OV))
        np.random.RandomState(0).shuffle(base)
        arf = forest.ARFClassifier(n_models=10, seed=0)
        bn = [names[i] for i in beh]
        for i in base:
            arf.learn_one(dict(zip(bn, map(float, Xt[i, beh]))), int(yt[i]))

        def rec(idx):
            if len(idx) == 0:
                return None
            return round(float(np.mean([int(arf.predict_one(dict(zip(bn, map(float, Xf[i, beh])))) or 0) for i in idx])), 4)

        before_ps = rec(ps_test)
        before_bf = round(float(np.mean([int(arf.predict_one(dict(zip(bn, map(float, Xt[i, beh])))) or 0) for i in atk_t])), 4)
        # learn Friday PortScan (oversampled, interleaved benign)
        fbenign = np.random.RandomState(1).choice(np.where(yf == 0)[0], size=min(int((yf == 0).sum()), 10 * len(ps_learn)), replace=False)
        ls = list(np.repeat(ps_learn, OV)) + list(fbenign)
        np.random.RandomState(2).shuffle(ls)
        for i in ls:
            arf.learn_one(dict(zip(bn, map(float, Xf[i, beh]))), int(yf[i]))
        rep["self_learning_withheld_portscan"] = {
            "portscan_learn": int(len(ps_learn)), "portscan_test(untouched)": int(len(ps_test)),
            "before": {"withheld_PortScan_recall": before_ps, "known_Tuesday_bruteforce_recall": before_bf},
            "after": {"withheld_PortScan_recall(untouched)": rec(ps_test),
                      "Tuesday_bruteforce_recall(forgetting)": round(float(np.mean([int(arf.predict_one(dict(zip(bn, map(float, Xt[i, beh])))) or 0) for i in atk_t])), 4)},
            "note": "genuinely independent withheld family: Friday portscan+ddos+botnet, different day/tool"}
    except Exception as e:
        rep["self_learning_withheld_portscan"] = {"error": str(e)[:300]}

    json.dump(rep, open(out, "w"), indent=1, default=str)
    print(json.dumps(rep, indent=1, default=str)[:4000])


if __name__ == "__main__":
    main()
