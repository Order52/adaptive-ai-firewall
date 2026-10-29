# Revised capability assessment (after the offline audit)

Written 2026-10-29, incorporating the independent audit of the offline CIC-IDS2017 results
(`OFFLINE_CIC_AUDIT.md`) and the self-learning demonstration. This is the honest answer to
"does the project demonstrate each capability?", with the evidence and the limits.

**Golden rule kept throughout:** an offline external-dataset result is a **separate gate**
and never advances the **live GNS3** gate (`GATE_STATES.md`). Live attack detection stays
BLOCKED (no in-lab attack traffic; generating it is a safety boundary).

| Capability | Verdict | Basis and limits |
|---|---|---|
| **Genuine malicious-behaviour learning** | **Yes for brute force, offline (audited); family-specific; not on the live lab** | RF detects brute force at 0.846 (CI [0.78, 0.90]), 0 FP on 13,499 windows; **audited as behavioural, not identity** (behaviour-only 0.85–0.90, identity-only 0.0). **Independent validation (`OFFLINE_INDEPENDENCE.md`): the model is FAMILY-SPECIFIC** — a brute-force model detects only 0.11 of a different day's attacks, and even trained on Friday detects only 0.27 (port-scan/botnet/DDoS are hard for window features). So it learns brute-force behaviour specifically, not universal attack detection. |
| **Novelty detection** | **Partial, with a real limit** | Benign side **proven on the lab**: NV2 0.0059 FPR on unseen users. Offline attack-side: cross-protocol within brute force (FTP→SSH 0.99, SSH→FTP 0.66) — not universal zero-day. **The fixed scan ceiling (15 ports/60 s) MISSES a real slow NMAP scan** (1 of 79 Friday attack windows; 0.9 % benign false-strong) — fixed ceilings catch fast scans only (`OFFLINE_INDEPENDENCE.md`). Live attack-novelty recall: BLOCKED. |
| **Improved future detection through adaptation** | **Yes (offline), modest, now on INDEPENDENT data** | On a **genuinely independent** capture (CIC Friday — different day/family/tool), a challenger learns the withheld family (recall 0.0 → **0.625** on untouched held-out) with **no forgetting** of Tuesday brute force (1.0) — `OFFLINE_INDEPENDENCE.md`. Earlier within-Tuesday demo: FTP 0.0 → 0.45. Modest absolute recall. **Batch vs incremental is comparable** (ARF recall 0.94 / batch 0.89; batch higher precision + slightly cheaper) — **no claim that continuous learning is superior.** |
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
