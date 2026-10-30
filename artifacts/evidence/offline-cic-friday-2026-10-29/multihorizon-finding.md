# Multi-horizon / threshold analysis of scan detection (#1), with benign-FPR guard (#7)

Offline, CIC-IDS2017 Friday real NMAP scan (attacker 172.16.0.1, 997 distinct ports;
23 benign sources). Max distinct destination ports in any sliding window, per horizon,
vs the benign false-positive rate at candidate thresholds:

| Horizon | attacker max ports | benign p99 | t15 FPR | t30 FPR | t50 FPR | t100 FPR |
|---|---|---|---|---|---|---|
| 60 s   | 997 | 48  | 0.13 | 0.09 | **0.00** | 0.00 |
| 300 s  | 997 | 66  | 0.35 | 0.09 | 0.04 | **0.00** |
| 900 s  | 997 | 71  | 0.48 | 0.09 | 0.09 | **0.00** |
| 1800 s | 997 | 76  | 0.52 | 0.09 | 0.09 | **0.00** |
| whole  | 997 | 197 | 0.57 | 0.52 | 0.35 | 0.04 |

**Corrected, honest findings:**
- The scan is NOT invisible: it has a concentrated **997-port burst within ~60 s**, which
  the fixed ceiling *does* catch (1 window). Most other Friday attacker windows are
  **botnet/DDoS with few ports** — correctly NOT flagged by a *scan* detector.
- The main lever is the **threshold, not the horizon**: the current **15 ports/60 s ceiling
  is too low** (13–57 % benign source FPR over longer horizons); a threshold of **50–100
  distinct ports detects this scan at 0 benign FP** at 60–1800 s horizons. Whole-capture
  aggregation is too broad (benign sources accumulate ports).
- Actionable (offline-validated, NOT yet applied to the live pipeline): raise the scan
  ceiling toward ~50–100 distinct ports and keep multi-horizon evaluation (60 s AND 300 s);
  any lab adoption must re-verify benign FPR on lab benign (#7) — the lab population differs
  from CIC, so the exact threshold must be re-calibrated there.
