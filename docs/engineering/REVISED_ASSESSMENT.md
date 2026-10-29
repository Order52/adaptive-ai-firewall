# Revised capability assessment (after the offline audit)

Written 2026-10-29, incorporating the independent audit of the offline CIC-IDS2017 results
(`OFFLINE_CIC_AUDIT.md`) and the self-learning demonstration. This is the honest answer to
"does the project demonstrate each capability?", with the evidence and the limits.

**Golden rule kept throughout:** an offline external-dataset result is a **separate gate**
and never advances the **live GNS3** gate (`GATE_STATES.md`). Live attack detection stays
BLOCKED (no in-lab attack traffic; generating it is a safety boundary).

| Capability | Verdict | Basis and limits |
|---|---|---|
| **Genuine malicious-behaviour learning** | **Yes, offline (audited); not on the live lab** | On real recorded brute force, RF detects at 0.846 (CI [0.78, 0.90]), 0 FP on 13,499 benign windows. **Audited as behavioural, not host/port identity:** behaviour-only features 0.85–0.90, identity-only 0.0, survives a 300 s anti-overlap gap. Limits: CIC-domain only; two brute-force protocols; the signal is partly tool-shaped ("no DNS + repetitive connections"); not shown in the lab. |
| **Novelty detection** | **Partial** | Benign side **proven on the lab**: NV2 one-shot 0.0059 FPR on unseen users. Attack-side (offline): a behaviour-only model trained on FTP detects **withheld SSH** at 0.99 (cross-protocol generalisation within brute force — **not** universal zero-day); SSH→FTP 0.66. Unsupervised novelty on CIC: 0.94 recall but 3.8 % FPR. Live attack-novelty recall: BLOCKED. |
| **Improved future detection through adaptation** | **Partial, offline, modest** | Self-learning demo: a challenger that knows SSH (0.94) but misses withheld FTP (0.0) learns FTP incrementally and improves to **0.45 on untouched FTP** while **retaining SSH (0.98 — no catastrophic forgetting)**, 0 benign FP. Limits: one run per family (within-run holdout, not independent runs); modest absolute recall; offline. **No claim that continuous learning beats batch** — the earlier "frozen ARF 0.0" was a data-ordering artifact; fairly trained, RF ≈ ARF. |
| **Safe model governance** | **Yes (mechanisms + live boundary)** | The promotion gate runs **live** and correctly **refuses** an unqualified challenger (shown this session). Crash-consistent rollback, poison-resistant admission, checkpoints, delayed labels: in `ml/incremental.py` / the challenger lifecycle, unit-tested. **No model has been promoted** (nothing qualifies — the correct outcome). No gate was disabled. No unsafe promotion. |
| **Real network enforcement** | **Yes (gate D MET)** | Read-back-verified OPNsense/WAF actions; protected-address refusal shown live; shared-address guard; auto-expiry; isolation 41/41; live lab tests 14/14. |
| **Independent value beyond static rules** | **Not demonstrated** | Needs the five-way comparison (static / supervised / novelty / frozen-hybrid / adaptive) on **in-lab** attack runs (gate E, BLOCKED). Offline, the ML detects brute force, but a controlled static-vs-ML comparison on lab traffic has not been run. |

## Summary

**Proven on the live lab:** infrastructure, enforcement + safety guards, recovery
(incl. the FW01 OOM fix across reboots), governed-lifecycle refusal, and **benign**
generalisation (A4 logins, NV2 novelty).

**Proven offline on real recorded attack traffic (separate gate):** the feature pipeline +
supervised models learn **brute-force behaviour** (audited, not leakage) at 0 FP on the
sample; cross-protocol generalisation within brute force; a working — if modest —
self-learning improvement without forgetting.

**Not proven (needs in-lab attack runs, which only the authorised team can execute):**
live attack detection recall/FN (B), independent value over static rules (E), live
adaptation benefit, and any live promotion.

**Honest overall:** the project is a well-engineered, safety-first adaptive firewall with a
rigorous, self-audited methodology and real (if domain-limited and modest) evidence that
its learning detects genuine malicious behaviour — **not** a system that can yet claim
effective live attack detection or that continuous learning beats static approaches. Those
claims are deliberately withheld until the in-lab evidence exists.
