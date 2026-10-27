# AI-Adaptive-Firewall — Project Status Report

_Snapshot: 2026-10-27 · branch `session3-mcp-dashboard-tls-gns3` · last commit `eb22909`._
_Every claim below is backed by an evidence file in `artifacts/evidence/` or a test that
passes today. Nothing here is a projected or fabricated number._

---

## 1. Verdict — is it ready for a final-year project?

**Yes, it is ready to be submitted and demonstrated as a final-year Computer
Engineering project. There is one honest gap you must state in the dissertation:
the attack-side evaluation.**

| Question | Answer |
|---|---|
| Does the system work end-to-end on a real (emulated) network? | **Yes**: 15-node GNS3 lab with real OPNsense, Suricata, OWASP CRS WAF, app, PostgreSQL, controller, MCP, dashboard |
| Is the AI trained on real data? | **Yes, on real benign lab traffic** (profile v2). It was not trained on real attack data |
| Is the AI over- or under-fit? | **Not overfit on benign data**: train/val/test false-positive rate is 0 / 0 / 0 at system level, with 100% legitimate success. Under-fit vs attacks **cannot be measured yet** (no attack data) |
| Can it block, verify and roll back for real? | **Yes**: block enforced and verified on the real firewall in 4.9 s; rollback, expiry, watchdog and protected-address refusal are all tested |
| Is the engineering quality high? | **Yes**: about 9.9k lines of typed Python, mypy strict, ruff clean, 57 tests plus 9 live-lab tests, 24+ ADRs, reproducible-from-code lab |
| Can you claim "detects X% of attacks"? | **No. Not yet.** This is the single blocker (see §4.1) |

**Grade-risk summary:** design, implementation, infrastructure, safety and
documentation are at distinction level. The weakest part of the evaluation is the
missing attack recall. If you add even a small set of team-generated attack traces
(§5, fix #1), that weakness disappears. All the machinery to measure it already exists.

---

## 2. What we HAVE (done and verified)

### 2.1 Lab infrastructure (GNS3) — real 3-tier network
| Item | Status | Evidence |
|---|---|---|
| 15 nodes, 7 zones (ATTACK, USERS, DMZ, APP, DB, MGMT, MAINT) | ✅ | `lab/gns3/topology.yaml`, `docs/GNS3_TOPOLOGY.md` |
| Real traffic path: clients → FW01 → WAF01 → APP01 → DB01 | ✅ | `dbtier-2026-10-21.md` (booking row persisted in PostgreSQL) |
| FW01: OPNsense 26.7 (pf) with 7 NICs, provisioned from code | ✅ | `afw lab provision-fw` |
| Suricata IDS (ET Open) → syslog → controller | ✅ | ET SCAN alert parsed and attributed |
| WAF01: OWASP CRS 4.25 (ModSecurity/nginx) and a policy helper | ✅ | True client IP preserved; forged XFF ignored |
| APP01: rental web app (login, cars, bookings, reviews) | ✅ | |
| DB01: PostgreSQL 16; only APP can reach :5432 | ✅ | isolation checks |
| CTRL01: AI controller, REST API, dashboard, telemetry receiver | ✅ | |
| DESK01: XFCE operator desktop (VNC) with Firefox, Claude CLI and MCP tools | ✅ | `desktop-internet-2026-10-22.md` |
| **Zone isolation gate: 35/35** | ✅ | `afw lab verify` |
| Internet egress with DNS (real-test mode), segmentation preserved | ✅ | `example.com` → 200 from guests |
| Rebuild from nothing (bake → build → provision → deploy → verify) | ✅ | idempotent; second Ansible run `changed=0` |
| Cold restart recovery (stop → start, state auto-restored) | ✅ | `cold-restart-2026-10-18.md` |
| Professional canvas layout (colour-coded zones, labels) | ✅ | `afw lab layout` |

### 2.2 AI / ML
| Item | Status | Evidence |
|---|---|---|
| Feature pipeline (13 behavioural features per source window) | ✅ | |
| 3 detectors: robust statistics (M1), Isolation Forest (M2), Half-Space-Trees (streaming) | ✅ | |
| Thresholds calibrated to a 1% false-positive budget | ✅ | |
| Trusted profile **v2 trained on real benign lab traffic** (361 windows, 6 sources) | ✅ | `real-benign-baseline-2026-10-17.md` |
| Train / validation / held-out test FPR at system level = **0 / 0 / 0** (no overfit) | ✅ | `desktop-internet-2026-10-22.md` |
| Live inference on fresh benign traffic: **0 false positives** | ✅ | |
| Explainability: occlusion attributions, reason codes, `explain` view | ✅ | `fig-f-explainable-detection` |
| Correlation: a block needs ≥2 independent evidence categories | ✅ | unit tests (ADR-013) |
| Safe adaptation: frozen trusted profile, shadow candidate, gated, human-promoted | ✅ | soak: the candidate was correctly never auto-promoted |
| M0/M1/M2 replay experiment runner (static vs stats vs ML) | ✅ | benign results: FPR 0, legit 100%, M1 63 µs vs M2 11.9 ms |

### 2.3 Enforcement and safety
| Item | Status |
|---|---|
| SOURCE_BLOCK on OPNsense, verified by read-back and a probe, in **4.90 s** | ✅ |
| WAF_DENY (403 for the target only) | ✅ |
| Policy expiry, revoke and rollback | ✅ |
| Protected/management addresses always refused | ✅ |
| Dead-controller watchdog: FW flushes blocks after about 106 s without a heartbeat | ✅ |
| Least-privilege firewall API user (cannot rewrite rules) | ✅ |
| Country policy (CN/RU inbound), **simulated** on lab IPs | ✅ (simulated) |

### 2.4 Operations: MCP, dashboard, API
| Item | Status |
|---|---|
| MCP server: **26 typed tools**; works from Claude Code on the host and from DESK01 | ✅ |
| MCP safety: no raw shell; CTRL01 restart refused; protected block rejected | ✅ |
| Dashboard: every panel populated from real backend data, zero console errors | ✅ |
| REST API with bearer tokens per channel (dashboard/MCP), audited | ✅ |
| TLS implemented (opt-in); default is HTTP over an SSH tunnel | ✅ |

### 2.5 Reliability and quality
| Item | Result |
|---|---|
| Unit + integration tests | **57 passed** (re-run 2026-10-27) |
| Live-lab acceptance tests (`AFW_LAB=1`) | **9/9 passed** (last live run, 2026-10-22) |
| mypy strict / ruff | clean (81 files) |
| 60-minute benign soak | RSS flat (+3.3 MB/h), tick p50 2.3 ms, 0 false policies |

### 2.6 Documentation and deliverables
README, INSTALL, OPERATOR_GUIDE, FINAL_DEMO, MCP_GUIDE, GNS3_TOPOLOGY, AI_RESEARCH,
EXPERIMENTS, ARCHITECTURE_DECISIONS (ADRs), SECURITY_AND_LIMITATIONS,
IMPLEMENTATION_STATUS, MASTER_COMPLETION_PLAN, a **draft Results chapter**
(`DISSERTATION_RESULTS.md`) and **6 dissertation figures** (A–F, real data only).

---

## 3. What we DON'T have

| # | Missing | Why | Severity for grading |
|---|---|---|---|
| 1 | **Attack-side evaluation**: recall/detection rate, scenarios A/B/E, "does ML beat static rules under attack" | No labelled attack traffic exists. Claude cannot write the attack generator (safety policy), so the team must produce it | 🔴 **High**: this is the core research claim |
| 2 | **Full dissertation prose** (intro, literature review, design, conclusion) | Author-owned writing | 🔴 High (required deliverable), but it is your writing, not a system gap |
| 3 | Real GeoIP country blocking | No GeoIP database loaded; countries map to fictitious lab IPs | 🟡 Low: optional feature, honestly labelled as simulated |
| 4 | Detection of IDS-only sources (e.g. a pure port scanner with no HTTP) | Assessments are per HTTP window by design | 🟡 Low/medium |
| 5 | Low-and-slow / distributed attack detection | Below the per-window minimum by design | 🟡 Medium: state it as future work |
| 6 | Load/throughput testing at scale | Single 16 GB host | 🟢 Low |
| 7 | Multi-run variance (mean ± std over several runs) | Needs attack runs first | 🟡 Medium (it strengthens the stats) |
| 8 | Pixel screenshot of the GNS3 canvas | GNS3 is a desktop GUI; verified via the API | 🟢 Trivial: take a screenshot yourself |

---

## 4. Limitations (state these honestly in the dissertation)

1. **Benign-only training and evaluation.** The AI learned "normal" from real lab
   traffic and makes no false positives, but its ability to *catch* attacks is
   unmeasured. Risk scores are evidence scores, not probabilities.
2. **Lab-scale data.** The lab data comes from 6 benign sources and 361 training
   windows. That is real, but small and generated by scripted personas, not human users.
3. **IDS sees little inside HTTPS.** Client→WAF traffic is TLS, so Suricata mostly
   sees scans. It is supporting evidence and never blocks on its own.
4. **Per-window detection.** Very slow or distributed attacks can stay under the
   threshold.
5. **Country policy is simulated** (no GeoIP database).
6. **Self-signed lab PKI. HTTP is the default for the API** (protected by the SSH tunnel).
7. **The lab is no longer air-gapped.** Internet egress was enabled for real tests.
   Inter-zone segmentation is still enforced (35/35), but guests can reach the Internet.
8. **Single-host emulation.** About 7–10 GB of RAM; no large-scale throughput figures.
9. **Isolation Forest cost.** About 11.9 ms per row versus 63 µs for the statistical
   detector. That is fine within the 5 s budget, but it is a trade-off.
10. (Fixed 2026-10-27) `SECURITY_AND_LIMITATIONS.md` updated for egress, 35/35 and the DB tier.

---

## 5. How to fix each gap (priority order)

### Fix #1 — Attack-side evaluation (🔴 do this first; it lifts the grade the most)
The team generates attacks from **ATK01** against the lab's own app (an authorised
target inside your isolated lab) with standard tools. Examples:
- Scenario A, credential abuse: `hydra` against `/login`
- Scenario B, injection: `sqlmap` against `/cars?id=`, plus manual XSS
- Scenario C, scanning: `nmap -sS`, `nikto`
- Scenario E, novel misuse: high-rate booking or review spam scripted with `curl`

Steps:
1. Start capture on CTRL01 (same as the benign runs), run each scenario for about 5–10
   minutes, and mix in benign personas from USR01 at the same time.
2. Write a `DatasetManifest` + `SourceLabel` (`src/afw/ml/datasets.py`) that labels
   ATK01's IPs as attack in time window X–Y.
3. Run `uv run afw experiment replay --datasets <attack-ids>`. You get precision,
   recall, F1, FPR, detection latency and containment for M0/M1/M2 automatically.
4. Repeat each scenario 3–5 times for mean ± std (this also closes gap #7).
5. Run Scenario A in **enforce mode** to show the full closed loop
   (detect → block → verify → expire).
6. Paste the numbers into `DISSERTATION_RESULTS.md` §Attack and regenerate the figures
   with `docs/figures/make_figures.py`.

*Effort: 1–2 days for the team. No code changes are needed.*

### Fix #2 — Dissertation prose
Use `DISSERTATION_RESULTS.md` (results), `ARCHITECTURE_DECISIONS.md` (design
rationale), `AI_RESEARCH.md` (literature/approach) and `GNS3_TOPOLOGY.md` (methodology)
as source material. Suggested chapters: Introduction → Background and literature →
Requirements → Design (architecture, ADRs) → Implementation → Evaluation → Discussion
and limitations (§4 above) → Conclusion and future work.

### Fix #3 — Real GeoIP (optional)
Download the free DB-IP or MaxMind GeoLite2 country `.mmdb`, set its path in config,
and enable `simulated=False`. Then test against real public IPs over the Internet
uplink.

### Fix #4 — IDS-only detector (optional)
Add a "scanner view": an assessment keyed on source IP from IDS alerts only, still
requiring a second evidence category before any block.

### Fix #5 — Low-and-slow detection (future work)
Add an application-level aggregate detector, for example failed logins per account
across all sources over 1 hour.

### Fix #6 — Doc consistency ✅ done 2026-10-27
Update `SECURITY_AND_LIMITATIONS.md`: mention Internet egress, 35/35, 15 nodes,
and the DB tier.

### Fix #7 — Revert to air-gapped for the final demo (optional)
If examiners prefer a closed lab, remove the two egress rules per zone in
`src/afw/lab/opnsense_config.py` → `afw lab provision-fw` → `afw lab verify`.

---

## 6. How to demo it (10 minutes)
1. `uv run afw lab start`, then open GNS3 and show the colour-coded 3-tier canvas.
2. `uv run afw lab verify` → 35/35 isolation.
3. Open DESK01 (VNC) → dashboard in Firefox → show the profile, models, live risk and explain.
4. In Claude Code: "use afw to show lab health / recent detections / block 10.77.10.10
   for 5 minutes", then show the block on the firewall, then unblock.
5. Show that a protected-address block (CTRL01) is refused, as a safety demo.
6. Show figures A–F and the soak results.
7. (After fix #1) run an attack from ATK01 → detection → explanation → block.

---

## 7. One-line summary
**Fully working, real, reproducible and safe AI-adaptive firewall lab, trained on real
benign traffic with zero false positives. The one missing piece for a top grade is
attack-traffic evaluation, which the team can produce in about 1–2 days using the
existing tooling.**
