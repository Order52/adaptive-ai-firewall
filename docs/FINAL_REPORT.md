# Final report — self-learning network firewall

**2026-10-29.** Direct answers to: what has actually been demonstrated, what failed, what
remains blocked, and whether the system satisfies the original vision. Everything here is
backed by evidence under `artifacts/evidence/`; nothing is asserted without a measurement.
Offline recorded-traffic results are on a **separate gate** and never advance the live GNS3
gate (`engineering/GATE_STATES.md`).

---

## 1. What has actually been demonstrated

**On the live lab (real, verified):**
- Reproducible 8-VM lab, zone isolation **41/41**, idempotent deploy, whole-lab
  cold-restart recovery, and **self-recovery** from the (institutional) host's unattended
  reboots (GNS3 auto_start).
- mTLS telemetry with loss-free delivery under controlled faults; heartbeats expose stale
  sensors; captured datasets equal the WAF log exactly.
- **Enforcement**: read-back-verified OPNsense/WAF blocks and rate limits, auto-expiry,
  protected-address refusal (shown live), shared-address guard.
- **Safety**: an anomaly alone never blocks (≥ 2 independent evidence categories); stale
  sensors pause automatic enforcement.
- **Governed learning lifecycle runs live** and correctly **refuses** promotion of an
  unqualified challenger (shown live).
- **Benign generalisation proven**: login controls (A4) 0.0 FPR on households/shared
  addresses, 0/2 791 logins refused; network novelty (NV2) 0.0059 FPR on 22 unseen users.
- **FW01 Suricata OOM fixed** (2560 MB + 1 GB swap), persistent across **3 reboots** via a
  boot hook; net_dns telemetry confirmed working.

**Offline, on real recorded attack traffic (CIC-IDS2017; separate gate; audited):**
- The feature pipeline + a RandomForest detect **brute force** at **0.846 recall
  (CI [0.78, 0.90]), 0 FP on 13,499 benign windows** — **audited as behaviour-driven, not
  host/port-identity leakage** (behaviour-only features 0.85–0.90; identity-only 0.0;
  survives a 300 s anti-overlap gap).
- **Self-learning on a genuinely independent capture** (CIC Friday — different day, family
  and tool): a challenger learns the withheld family (recall **0.0 → 0.625** on untouched
  held-out) with **no catastrophic forgetting** of the earlier family (1.0). This is the
  strongest adaptation evidence in the project.
- Cross-protocol generalisation **within** brute force (FTP → withheld SSH 0.99).

## 2. What failed / the honest limits

- **The models are family-specific.** A brute-force model detects only **0.11** of a
  different day's attacks; even trained on Friday, detection is only **0.27** (port scan /
  botnet / DDoS are hard for window-level behaviour features). It learned brute-force
  behaviour, **not** a universal attack detector.
- **The fixed scan ceiling misses a real slow scan.** A 997-port NMAP scan spread over the
  afternoon triggered the 15-ports/60 s ceiling in only **1 of 79** windows (0.9 % benign
  false-strong). Fixed ceilings catch fast scans only.
- **Incremental ≯ batch.** A fair prequential comparison: ARF recall 0.94 but precision
  0.77 / FPR 0.0045; periodic batch RF recall 0.89 but precision 0.90 / FPR 0.0016 and
  slightly cheaper to train. **No "continuous learning is superior" claim.**
- **Earlier overclaims were corrected by audit:** the "frozen ARF 0.0" was a data-ordering
  artifact; "SSH→FTP 0.0" was a port-feature artifact; "0 FP" is sample-bounded (CI upper
  ≈ 0.0003), not absolute; "FTP→SSH 0.99" is not universal zero-day.
- **No eligible champion** from P6/P7/A3 model selection on the lab (A4 fixed only the
  benign/household side); the trusted v2 over-fits and stays monitor-only.
- **Offline ≠ lab.** All offline results are CIC-domain and do **not** transfer to the lab
  without re-training (different benign population). They can **never** advance the live gate.

## 3. What remains blocked

**Live GNS3 attack detection (gates B, E, the live half of C and G).** This needs attack
traffic executed in the lab from ATK01. Generating it is a **safety-enforced boundary** for
this agent (it fired when attempted); I respect it and will not circumvent it. Everything
downstream is ready and will run automatically once the authorised team records the runs
(`docs/TEAM_ATTACK_QUICKSTART.md`): the five-way comparison (→ B, E), supervised + new-threat
in-lab evaluation, in-lab novelty recall, a governed promotion if a candidate qualifies
(→ C), and the team demo (→ G).

## 4. Does it satisfy the original vision of a self-learning network firewall?

**Partially, and honestly measured — not a finished, proven self-learning firewall.**

| Vision element | Verdict |
|---|---|
| Learns legitimate behaviour (benign) | **Yes, proven on the lab** (A4, NV2) |
| Learns known malicious behaviour | **Yes for brute force, offline & audited; family-specific; not on the lab** |
| Recognises previously unfamiliar malicious behaviour | **Partial** — cross-protocol within brute force; **fixed scan detection misses slow scans**; live recall blocked |
| Improves future detection through adaptation | **Yes, offline, on independent data (0 → 0.625, no forgetting); modest**; not better than batch; not shown live |
| Safe model governance | **Yes** — gate refuses unqualified promotion live; nothing promoted; gates intact |
| Real network enforcement | **Yes** — verified, read-back, guards, 41/41 |
| Independent value beyond static rules | **Not demonstrated** — needs the in-lab five-way comparison |

**Summary.** The project is a genuinely engineered, safety-first adaptive firewall with a
rigorous, **self-audited** methodology. It **demonstrates real — if modest and
domain-limited — self-learning**: on a completely independent capture it learns a new
attack family without forgetting the old one. It does **not** yet demonstrate effective,
general, live attack detection, and it does **not** show that adaptation beats static
approaches. Those claims are deliberately withheld until in-lab evidence exists. By the
project's own honest standard — *meaningful, independently measurable adaptation and
reliable protection, not artificial detection numbers* — it has achieved the **reliable
protection** and **governance** fully, and the **measurable adaptation** partially and
offline; the live-attack proof remains the one external, safety-gated step.

---

*Supporting detail:* `COMPLETE_DOSSIER.md`, `engineering/OFFLINE_CIC_AUDIT.md`,
`OFFLINE_INDEPENDENCE.md`, `REVISED_ASSESSMENT.md`, `GATE_STATES.md`, `RESULTS.md`.
