"""Offline evaluation on recorded real attack traffic (CIC-IDS2017 Tuesday).

PROVENANCE: this is an EXTERNAL recorded packet capture (CIC-IDS2017, UNB), processed
OFFLINE with Suricata (-r, no packets on any network). It is NOT an attack executed in
our GNS3 lab, and its result feeds a SEPARATE gate ("offline recorded-attack detection"),
never the live GNS3 attack gate.

Pipeline (reuses our production code):
  Suricata eve.json (flow/dns/tls/ssh)  -> afw.telemetry.parsers.lines.parse_suricata_net
    -> afw.domain.network.NetworkEvent
    -> afw.features.network.NetworkWindows(services=frozenset())   # all flows count
    -> per-source 30 s-emission NetworkVectors (our 28x2 network features)
  Ground-truth label: a source-window is ATTACK iff the source is a CIC attacker address
  (brute force from the Kali host); else BENIGN. (Authoritative CIC ground truth by
  attacker IP + attack day, which sidesteps the CICFlowMeter label defects of Engelen et
  al. 2021.)

Models (run-/time-aware split; attacker and victim never leak across split by time):
  - RandomForest (sklearn) -- the batch baseline.
  - River ARFClassifier -- the incremental classifier, predict-before-learn.
  - NetworkNovelty (our unsupervised detector) calibrated on CIC BENIGN only (domain-
    adapted to CIC), tested on CIC attack -- reported separately.

usage: cic_offline_eval.py <eve.json> <out.json>
"""
import json
import sys
from datetime import datetime, timezone
from ipaddress import IPv4Address, ip_address

import numpy as np

from afw.features.network import FEATURE_NAMES, NetworkWindows
from afw.ml.network_detector import NetworkNovelty
from afw.telemetry.parsers.lines import is_network_event, parse_suricata_net

# CIC-IDS2017 Tuesday ground truth (UNB + WTMC-2021 extended doc):
#   attacker Kali 205.174.165.73 (NAT 172.16.0.1 / 205.174.165.80); victim 192.168.10.50.
#   FTP-Patator 09:17-10:30, SSH-Patator 13:00-16:11 (local). We label by attacker IP:
#   on Tuesday the Kali host's traffic is the brute force (reported with its port mix).
ATTACKERS = {IPv4Address(a) for a in ("205.174.165.73", "172.16.0.1", "205.174.165.80")}
EVERY_S = 30


def build(eve_path):
    """Stream eve.json, build NetworkEvents, emit per-source labelled feature vectors."""
    w = NetworkWindows(frozenset(), every_s=EVERY_S)  # services empty: every flow counts
    rows, labels, times, srcs, ssh_ftp = [], [], [], [], []
    last_emit = None
    n_events = 0

    def flush(now):
        for v in w.emit(now):
            atk = v.source_ip in ATTACKERS
            rows.append(v.as_row())
            labels.append(int(atk))
            times.append(v.window_end)
            srcs.append(str(v.source_ip))

    with open(eve_path, errors="replace") as fh:
        for line in fh:
            if '"event_type"' not in line:
                continue
            try:
                p = json.loads(line)
            except ValueError:
                continue
            if not is_network_event(p):
                continue
            try:
                ev = parse_suricata_net(p, sensor_id="cic-offline")
            except Exception:
                continue
            n_events += 1
            w.add(ev)
            t = ev.observed_at
            if last_emit is None:
                last_emit = t
            # drive emissions forward in 30 s steps as pcap time advances
            while t - last_emit >= w.every:
                last_emit = last_emit + w.every
                flush(last_emit)
    flush((last_emit or datetime.now(timezone.utc)))
    return (np.array(rows, dtype=float), np.array(labels), times, srcs, n_events)


def metrics(y_true, y_pred):
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    rec = tp / (tp + fn) if tp + fn else None
    prec = tp / (tp + fp) if tp + fp else None
    fpr = fp / (fp + tn) if fp + tn else None
    return {"recall": rec, "precision": prec, "fpr": fpr, "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def main():
    eve, out = sys.argv[1], sys.argv[2]
    X, y, times, srcs, n_events = build(eve)
    report = {
        "provenance": "EXTERNAL CIC-IDS2017 Tuesday, Suricata offline (-r); NOT a GNS3 lab run",
        "n_network_events": n_events,
        "n_windows": int(len(y)),
        "n_attack_windows": int(y.sum()),
        "n_benign_windows": int((y == 0).sum()),
        "attacker_sources": sorted({s for s, a in zip(srcs, y) if a}),
        "feature_schema": list(FEATURE_NAMES),
    }
    if y.sum() == 0 or (y == 0).sum() == 0:
        report["error"] = "need both attack and benign windows; check attacker IPs / capture point"
        json.dump(report, open(out, "w"), indent=1, default=str)
        print(json.dumps(report, indent=1, default=str)[:2000])
        return

    # time-aware split: first 60% of windows (by time) train, last 40% test
    order = np.argsort([t.timestamp() for t in times])
    Xo, yo = X[order], y[order]
    cut = int(0.6 * len(yo))
    Xtr, ytr, Xte, yte = Xo[:cut], yo[:cut], Xo[cut:], yo[cut:]
    report["split"] = {"train": int(len(ytr)), "train_attack": int(ytr.sum()),
                       "test": int(len(yte)), "test_attack": int(yte.sum())}

    # --- RandomForest baseline ---
    from sklearn.ensemble import RandomForestClassifier
    if ytr.sum() and (ytr == 0).sum():
        rf = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=0, n_jobs=-1)
        rf.fit(Xtr, ytr)
        report["random_forest"] = metrics(yte, rf.predict(Xte))

    # --- River ARF (incremental): two evaluations ---
    # (a) batch-style, same split as RF (train then predict test, no learning on test).
    # (b) prequential (the natural streaming mode): on the time-ordered stream, after a
    #     warmup, predict-BEFORE-learn each window, then learn it. Recall/FPR scored on
    #     windows after the warmup. This is the fair incremental evaluation.
    try:
        from river import forest

        names = list(FEATURE_NAMES)

        def new_arf():
            return forest.ARFClassifier(n_models=10, seed=0)

        # (a) batch-style, matching RF's split
        arf = new_arf()
        for xi, yi in zip(Xtr, ytr):
            arf.learn_one(dict(zip(names, map(float, xi))), int(yi))
        pa = [int(arf.predict_one(dict(zip(names, map(float, xi)))) or 0) for xi in Xte]
        report["river_arf_batch_split"] = metrics(yte, np.array(pa))

        # (b) prequential on the full time-ordered stream
        arf2 = new_arf()
        warm = max(500, int(0.2 * len(yo)))
        pstream, ystream = [], []
        for i, (xi, yi) in enumerate(zip(Xo, yo)):
            d = dict(zip(names, map(float, xi)))
            if i >= warm:
                pstream.append(int(arf2.predict_one(d) or 0))
                ystream.append(int(yi))
            arf2.learn_one(d, int(yi))  # learn after predicting (predict-before-learn)
        report["river_arf_prequential"] = metrics(np.array(ystream), np.array(pstream))
        report["river_arf_prequential"]["warmup_windows"] = warm
    except Exception as e:
        report["river_arf_prequential"] = {"error": str(e)[:200]}

    # --- Unsupervised network novelty, calibrated on CIC BENIGN (domain-adapted) ---
    try:
        det = NetworkNovelty()
        benign_tr = Xtr[ytr == 0]
        # calibrate wants NetworkVector objects; build light wrappers via as_row inverse
        from afw.features.network import NetworkVector as NV

        def wrap(x):
            return NV(source_ip=IPv4Address("0.0.0.0"), window_end=times[0],
                      values=dict(zip(FEATURE_NAMES, map(float, x))), n_events=1)
        det.calibrate([wrap(x) for x in benign_tr], min_windows=30)
        unf = np.array([det.assess(wrap(x)).unfamiliar for x in Xte])
        report["network_novelty_cic"] = metrics(yte, unf.astype(int))
        report["network_novelty_cic"]["note"] = "calibrated on CIC benign (domain-adapted); unsupervised"
    except Exception as e:
        report["network_novelty_cic"] = {"error": str(e)[:300]}

    # --- Held-out attack-family generalisation (withheld-family, P4) ---
    # Family of an attack window: SSH (ssh_flows_60 > 0, port 22) vs FTP (port 21, else).
    # Train a frozen RF on benign + ONE family; measure recall on the WITHHELD family
    # (predict-before-learn: the model never saw that family). Both are brute force but
    # different protocols, so this is a cross-family zero-day generalisation test.
    try:
        ssh_i = list(FEATURE_NAMES).index("ssh_flows_60")
        fam = np.array(["ssh" if (yi and X[i, ssh_i] > 0) else ("ftp" if yi else "benign")
                        for i, yi in enumerate(y)])
        report["family_counts"] = {f: int((fam == f).sum()) for f in ("benign", "ftp", "ssh")}
        from sklearn.ensemble import RandomForestClassifier as RFC
        benign_mask = fam == "benign"
        hof = {}
        for train_fam, test_fam in (("ftp", "ssh"), ("ssh", "ftp")):
            tr_mask = benign_mask | (fam == train_fam)
            if (fam == train_fam).sum() < 5 or (fam == test_fam).sum() < 5:
                hof[f"train_{train_fam}_test_{test_fam}"] = {"skip": "too few windows of a family"}
                continue
            clf = RFC(n_estimators=200, class_weight="balanced", random_state=0, n_jobs=-1)
            clf.fit(X[tr_mask], y[tr_mask])
            # recall on the WITHHELD family (unseen), and FPR on benign
            te_atk = fam == test_fam
            rec = float((clf.predict(X[te_atk]) == 1).mean())
            fpr = float((clf.predict(X[benign_mask]) == 1).mean())
            hof[f"train_{train_fam}_test_{test_fam}"] = {
                "withheld_family_recall": round(rec, 4), "benign_fpr": round(fpr, 4),
                "n_train_attack": int((fam == train_fam).sum()), "n_withheld": int(te_atk.sum())}
        report["held_out_family"] = hof
    except Exception as e:
        report["held_out_family"] = {"error": str(e)[:300]}

    json.dump(report, open(out, "w"), indent=1, default=str)
    print(json.dumps({k: v for k, v in report.items() if k != "feature_schema"}, indent=1, default=str)[:3000])


if __name__ == "__main__":
    main()
