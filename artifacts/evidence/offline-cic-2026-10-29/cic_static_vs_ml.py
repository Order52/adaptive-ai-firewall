"""Static Suricata vs supervised ML vs novelty vs hybrid, on the SAME offline traffic (#3).

Measures what the AI contributes INDEPENDENTLY of the static Suricata ET Open ruleset.
Window-level (30 s per source, as the ML uses) and source-level.

  - STATIC (Suricata, ET Open rules): a window is detected if the source has any alert in
    the window; reported both for ALL alerts and for ATTACK-CATEGORY alerts only (generic
    SURICATA STREAM/decoder anomalies are protocol noise, not attack detections).
  - SUPERVISED ML: RandomForest, behaviour-only, time-split (train past, test future).
  - NOVELTY: shipped NetworkNovelty fixed ceilings.
  - HYBRID: ML OR novelty.

Reports recall, FPR (benign), precision, CIs, and the alert-noise (distinct benign sources
Suricata alerts on). Separate offline gate.

usage: cic_static_vs_ml.py <flow_eve> <rules_eve> <out.json>
"""
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from cic_audit import BEHAVIOUR, groups_idx, wilson  # noqa: E402
from cic_offline_eval import ATTACKERS, FEATURE_NAMES, build  # noqa: E402

STREAM_NOISE = ("SURICATA STREAM", "SURICATA Applayer", "SURICATA zero length",
                "SURICATA decoder", "SURICATA Kerberos", "SURICATA ICMPv", "SURICATA UDP")


def load_alerts(rules_eve):
    """Return {src_ip: [(ts, is_attack_category), ...]} from the rules eve.json."""
    out = {}
    benign_srcs, attack_category_srcs = set(), set()
    with open(rules_eve, errors="replace") as fh:
        for line in fh:
            if '"event_type":"alert"' not in line:
                continue
            try:
                p = json.loads(line)
            except ValueError:
                continue
            sig = p.get("alert", {}).get("signature", "")
            src = p.get("src_ip", "")
            try:
                ts = datetime.fromisoformat(p["timestamp"].replace("Z", "+00:00"))
            except Exception:
                continue
            is_attack = not sig.startswith(STREAM_NOISE)
            out.setdefault(src, []).append((ts, is_attack))
            benign_srcs.add(src)
            if is_attack:
                attack_category_srcs.add(src)
    return out, benign_srcs, attack_category_srcs


def main():
    flow_eve, rules_eve, out = sys.argv[1], sys.argv[2], sys.argv[3]
    names = list(FEATURE_NAMES)
    beh = groups_idx(names, BEHAVIOUR)
    X, y, times, srcs, _ = build(flow_eve)
    alerts, alerted_srcs, attack_cat_srcs = load_alerts(rules_eve)

    # per-window Suricata detection: any alert for this source within the 60 s window
    def suricata_hit(i, attack_only):
        s = srcs[i]
        if s not in alerts:
            return 0
        lo = times[i] - timedelta(seconds=60)
        for ts, is_atk in alerts[s]:
            if lo <= ts <= times[i] and (is_atk or not attack_only):
                return 1
        return 0

    sur_any = np.array([suricata_hit(i, False) for i in range(len(y))])
    sur_atk = np.array([suricata_hit(i, True) for i in range(len(y))])

    # ML + novelty on behaviour-only, time-split
    order = np.argsort([t.timestamp() for t in times])
    Xo, yo = X[order][:, beh], y[order]
    cut = int(0.6 * len(yo))
    from sklearn.ensemble import RandomForestClassifier
    ml_pred = np.zeros(len(yo), dtype=int)
    if yo[:cut].sum() and yo[cut:].sum():
        rf = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0, n_jobs=-1)
        rf.fit(Xo[:cut], yo[:cut])
        ml_pred[cut:] = rf.predict(Xo[cut:])
    # novelty on full behaviour-horizon features
    from ipaddress import IPv4Address

    from afw.features.network import NetworkVector as NV
    from afw.ml.network_detector import NetworkNovelty
    det = NetworkNovelty()

    def wrap(x):
        return NV(source_ip=IPv4Address("0.0.0.0"), window_end=times[0],
                  values=dict(zip(FEATURE_NAMES, map(float, x))), n_events=1)
    nov = np.array([int(det.assess(wrap(X[order][k])).strong) for k in range(len(yo))])

    def m(pred, yv, mask=None):
        if mask is None:
            mask = np.ones(len(yv), dtype=bool)
        p, yy = np.array(pred)[mask], np.array(yv)[mask]
        tp = int(((p == 1) & (yy == 1)).sum()); fp = int(((p == 1) & (yy == 0)).sum())
        fn = int(((p == 0) & (yy == 1)).sum()); tn = int(((p == 0) & (yy == 0)).sum())
        return {"recall": round(tp / (tp + fn), 4) if tp + fn else None, "recall_ci95": wilson(tp, tp + fn),
                "precision": round(tp / (tp + fp), 4) if tp + fp else None,
                "fpr": round(fp / (fp + tn), 6) if fp + tn else None, "tp": tp, "fp": fp, "fn": fn}

    test = np.zeros(len(yo), dtype=bool); test[cut:] = True
    sur_any_o, sur_atk_o = sur_any[order], sur_atk[order]
    total_benign_srcs = len({s for s, a in zip(srcs, y) if not a})
    rep = {
        "provenance": "CIC-IDS2017 offline; behaviour-only ML; time-split test; separate gate",
        "windows": int(len(y)), "attack_windows": int(y.sum()),
        "suricata_alert_noise": {"distinct_sources_alerted": len(alerted_srcs),
                                 "distinct_sources_attack_category": len(attack_cat_srcs),
                                 "total_benign_sources": int(total_benign_srcs),
                                 "attacker_in_attack_category": any(a in attack_cat_srcs for a in map(str, ATTACKERS))},
        "window_level_test_split": {
            "static_suricata_all_alerts": m(sur_any_o, yo, test),
            "static_suricata_attack_category_only": m(sur_atk_o, yo, test),
            "supervised_ml": m(ml_pred, yo, test),
            "novelty_ceilings": m(nov, yo, test),
            "hybrid_ml_or_novelty": m(((ml_pred == 1) | (nov == 1)).astype(int), yo, test),
        },
        "what_ai_adds": {
            "attacks_ml_catches_that_suricata_attackcat_misses":
                int(((ml_pred == 1) & (sur_atk_o == 0) & (yo == 1) & test).sum()),
            "attacks_suricata_attackcat_catches_that_ml_misses":
                int(((sur_atk_o == 1) & (ml_pred == 0) & (yo == 1) & test).sum()),
        },
    }
    json.dump(rep, open(out, "w"), indent=1, default=str)
    print(json.dumps(rep, indent=1, default=str)[:3500])


if __name__ == "__main__":
    main()
