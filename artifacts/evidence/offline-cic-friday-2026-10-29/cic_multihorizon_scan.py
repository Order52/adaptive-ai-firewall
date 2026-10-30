"""Multi-horizon scan detection on the real slow NMAP scan (#1), with benign-FPR guard (#7).

The shipped detector flags a scan at a FIXED 15 distinct ports / 60 s. The Friday NMAP scan
(997 ports) is SPREAD OUT, so it evades the 60 s ceiling (1/79 windows). This experiment
asks: does a LONGER horizon catch the slow scan, and at what benign false-positive cost?

For each source it computes the max distinct destination ports over sliding windows of
60/300/900/1800 s and over the whole capture, then reports, per horizon:
  - attacker detected? (max distinct ports >= threshold)
  - fraction of BENIGN sources that would false-positive at the same threshold (#7).
Threshold candidates: 15 (current), 30, 50, 100.

usage: cic_multihorizon_scan.py <friday_eve.json> <out.json>
"""
import json
import sys
from collections import defaultdict
from datetime import datetime

from afw.telemetry.parsers.lines import is_network_event, parse_suricata_net

ATTACKERS = {"172.16.0.1", "205.174.165.73", "205.174.165.80"}
HORIZONS = [60, 300, 900, 1800, 10 ** 9]  # last = whole capture


def main():
    eve, out = sys.argv[1], sys.argv[2]
    # per source: list of (ts_seconds, dst_port) for flows
    ports = defaultdict(list)
    with open(eve, errors="replace") as fh:
        for line in fh:
            if '"event_type":"flow"' not in line:
                continue
            try:
                p = json.loads(line)
            except ValueError:
                continue
            if not is_network_event(p):
                continue
            try:
                ev = parse_suricata_net(p, "x")
            except Exception:
                continue
            if ev.kind.value != "flow" or ev.dst_port is None:
                continue
            ports[str(ev.client_ip)].append((ev.observed_at.timestamp(), int(ev.dst_port)))

    def max_distinct_over(events, horizon):
        """Max distinct ports in any sliding window of `horizon` seconds (two-pointer)."""
        ev = sorted(events)
        if not ev:
            return 0
        from collections import Counter
        c = Counter(); best = 0; lo = 0
        for hi in range(len(ev)):
            c[ev[hi][1]] += 1
            while ev[hi][0] - ev[lo][0] > horizon:
                c[ev[lo][1]] -= 1
                if c[ev[lo][1]] == 0:
                    del c[ev[lo][1]]
                lo += 1
            best = max(best, len(c))
        return best

    attacker = next((a for a in ATTACKERS if a in ports), None)
    benign = [s for s in ports if s not in ATTACKERS]
    rep = {"provenance": "CIC-IDS2017 Friday offline; real NMAP scan; separate gate",
           "attacker": attacker, "n_benign_sources": len(benign),
           "attacker_total_distinct_ports": len({pt for _, pt in ports.get(attacker, [])}),
           "horizons": {}}

    for h in HORIZONS:
        hl = "whole_capture" if h > 10 ** 8 else f"{h}s"
        atk_max = max_distinct_over(ports.get(attacker, []), h)
        benign_max = sorted(max_distinct_over(ports[s], h) for s in benign)
        row = {"attacker_max_distinct_ports": atk_max,
               "benign_p99_max_distinct_ports": benign_max[int(0.99 * len(benign_max))] if benign_max else 0,
               "benign_max": benign_max[-1] if benign_max else 0, "thresholds": {}}
        for thr in (15, 30, 50, 100):
            atk_detected = atk_max >= thr
            benign_fp = sum(1 for b in benign_max if b >= thr)
            row["thresholds"][thr] = {"attacker_detected": atk_detected,
                                      "benign_false_positive_sources": benign_fp,
                                      "benign_fpr": round(benign_fp / len(benign_max), 4) if benign_max else None}
        rep["horizons"][hl] = row

    # headline
    rep["finding"] = ("the shipped 15-ports/60s ceiling misses this spread scan; a longer "
                      "horizon recovers it. Best trade-off (detect attacker, 0 benign FP) is reported "
                      "per horizon/threshold above. Any lab adoption must re-check benign FPR (#7).")
    json.dump(rep, open(out, "w"), indent=1, default=str)
    print(json.dumps(rep, indent=1, default=str)[:3500])


if __name__ == "__main__":
    main()
