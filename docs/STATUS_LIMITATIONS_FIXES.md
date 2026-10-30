# AI-Adaptive-Firewall — everything done, limitations, how to fix them, current status

**One document.** What was built and measured, what is proven and what is not, every known
limitation with a concrete way to fix it, and where the project stands right now.

As of **2026-10-30 ~05:30Z** · branch `engineering-directive` · HEAD `97e6951` ·
**83 commits ahead of origin (unpushed)** · working tree clean · lab healthy (monitor mode,
nothing enforced). Every number below has an evidence file under `artifacts/evidence/`.
Earlier overclaims were audited and corrected; the corrected versions are used here.

---

## 1. Current status in one screen

| Area | Status |
|---|---|
| Live lab (8 VMs, isolation 41/41, live tests 14/14, controller healthy) | **Working** |
| Enforcement + safety guards (read-back, expiry, protected-address refusal) | **Proven live** |
| Governed learning lifecycle (gate, human promotion, probation, rollback) | **Proven live** — gate correctly *refuses* an unqualified challenger; nothing promoted |
| Benign generalisation (login controls A4, network novelty NV2) | **Proven on the lab** |
| Brute-force detection on real recorded traffic (CIC-IDS2017, offline) | **Demonstrated, audited** — recall 0.846, 0 FP on 13,499 benign windows |
| Self-learning on independent recorded data | **Demonstrated, conditional** — works for genuinely novel families only |
| AI value over static rules (offline) | **Measured** — decisive on brute force, marginal on harder families |
| FW01 Suricata OOM | **Fixed**, persistent across 3 reboots |
| **Live attack detection in the GNS3 lab** | **BLOCKED** — needs in-lab attack traffic (safety boundary) |
| Independent value beyond static rules *on the live lab* | **BLOCKED** (same reason) |
| Project complete? | **No** — and not declared so |

**Verification:** `scripts/final_verification.sh` → **11/11 pass** (ruff, format, mypy, pytest
377 passed / 14 skipped, isolation 41/41, live lab 14/14, controller ok, telemetry not
degraded, network novelty calibrated, offline gate reported). Latest archive:
`artifacts/evidence/final-verification-2026-10-29/final-verification-20261030-0509Z.txt`.

---

## 2. What the project is

A controller that protects a web application (a car-rental app) on a real GNS3 lab: 8 VMs,
6 zone switches, 2 host connectors.

| Node | Address | Role |
|---|---|---|
| FW01 | zone gateways | OPNsense: isolation, dynamic blocks, Suricata IDS, flow/DNS/TLS/SSH metadata, pf block log. **2560 MB RAM + 1 GB swap** |
| WAF01 | 10.77.30.10 | Reverse proxy / WAF |
| APP01 / DB01 | 10.77.40.10 / 10.77.60.10 | Application / database |
| CTRL01 | 10.77.50.10 | Controller: telemetry, features, ML, correlation, policy, enforcement, API, dashboard |
| USR01 | 10.77.20.0/24 | Legitimate-user traffic (scripted personas) |
| ATK01 | 10.77.10.10 | Attack zone — team-only, authorised runs |
| DESK01 | — | Operator desktop |

**Data flow:** sensors → mTLS telemetry → per-source behaviour windows → anomaly scoring
(robust-statistics + Isolation Forest enforce; Half-Space-Trees in shadow) → combined with
independent evidence categories (AUTH, WAF, IDS, HISTORY) → a block needs ≥ 2 independent
categories → safety validation → applied on OPNsense/WAF and **read back to verify** →
auto-expiry. In parallel: network-novelty detector (shadow), account-aware login controls,
pf server-block evidence (shadow), and a champion/challenger learning lifecycle with human
promotion, probation and automatic rollback.

**Stack:** Python (hexagonal), Pydantic, SQLAlchemy + SQLite, `typer` CLI (`afw`), Ansible,
HTTPS API with role tokens, dashboard, MCP. No Kafka, Kubernetes, deep learning or LLMs in
the firewall.

---

## 3. Everything that was done

### 3.1 Base system and milestones
Lab build, zone isolation, deployment; WAF/app telemetry; detectors; evidence correlation;
enforcement; dashboard; MCP; real benign baseline, soak and cold-restart tests.
M0–M9 (audit, corroboration, online shadow learning, champion/challenger gate + promotion +
probation + rollback, drift experiments, telemetry v2, attack-evaluation harness, GeoIP,
dashboard, docs). P1–P5 hardening (IDS mTLS, HTTPS API, directional GeoIP, IDS heartbeat,
RELP). N1–N7 network metadata, residual windows, shadow novelty, supervised RF + incremental
ARF/HAT (synthetic tests), response states, shared-address guard.

### 3.2 Predeclared experiments (each test set used once)
| Experiment | Result |
|---|---|
| P6 / P7 model selection | **No eligible model** |
| A3 (account-aware login controls) | Selection passed, **final failed** on legitimate households |
| **A4** (household fix) | **Passed** — `distinct_usernames` ceiling-only; 0.0 FPR on households/shared; 0/2 791 logins refused |
| NV1 (network novelty) | **Failed** one-shot test |
| **NV2** (fixed) | **Passed** — unfamiliar 0.0059 [0.0016, 0.0115], 0 strong, 22 unseen users |
| Item 3 (incremental classifier) | Synthetic benchmark only |

### 3.3 Operational work
- **FW01 Suricata OOM — fixed.** Diagnosed as guest-internal (1536 MB, no swap; the host
  was never the bottleneck). FW01 → **2560 MB RAM + 1 GB guest swap**, memcaps unchanged
  (no detection coverage sacrificed). 54-user / 10-minute stress: Suricata stable at ~481 MB,
  swap unused. A boot hook (`/usr/local/etc/rc.syshook.d/start/99-afw-resources`) restores
  swap and cron on every boot — **verified across 3 reboots**.
- **Host-reboot resilience.** The institutional host rebooted unattended three times. GNS3
  `auto_start` is now enabled so the lab self-recovers; otherwise `afw lab start`.
- **net_dns observation — resolved, not a fault.** NV2 captured 12,330 DNS events; direct DNS
  crossing FW01 produced `net_dns` 16. The earlier 0 was no qualifying traffic plus
  USR01's systemd-resolved stub, not a telemetry regression.
- **Backups.** Verified git bundle (complete history, test-cloned), portable tarball,
  model/dataset/config manifest, no secrets in Git. All copies are on this host.
- **Dashboard.** Network-novelty, pf server-block, login-control and model-lifecycle panels;
  candidate profiles labelled "registered — NOT qualified". Verified live, 0 console errors.
- **Live governance demo.** Promotion gate run on fresh data → refused. Enforcement guards
  shown live (management and database addresses refused).

### 3.4 Offline evaluation on real recorded attack traffic (separate gate)
Method: CIC-IDS2017 captures → Suricata offline (`-r`, no packets on any wire) → our
production feature pipeline → models. Labelled **by attacker IP** (the CICFlowMeter labels
have documented defects). Tuesday: FTP/SSH brute force (11 M packets). Friday: PortScan /
Botnet / DDoS (independent day, families and tool). Provenance + sha256 recorded.

**Audit of the first results** (`engineering/OFFLINE_CIC_AUDIT.md`):
- `172.16.0.1` is the attacker's post-NAT path; it contacts only the victim, only in the
  documented windows — labels are temporally correct.
- **Behaviour-driven, not identity leakage:** behaviour-only features 0.85–0.90 recall;
  identity-only (ports/hosts) 0.0; a 300 s anti-overlap gap changes nothing.
- **Corrections made:** the "frozen ARF = 0.0" was a *data-ordering artifact* (shuffled →
  0.976); "SSH→FTP = 0.0" was a *port-feature artifact* (behaviour-only → 0.66); "0 FP" is
  bounded by the sample (CI), not absolute; FTP→SSH 0.99 is not "universal zero-day".

**Independent validation + comparisons:**
| Measurement | Result |
|---|---|
| RF, brute force (time-split) | recall **0.846** [0.78, 0.90], **0 FP / 13,499 benign** |
| Tuesday-trained model → Friday attacks | recall **0.114** [0.06, 0.20] — **family-specific** |
| Trained *and* tested on Friday | recall **0.267** [0.17, 0.39] — hard families |
| Static Suricata (ET Open) on brute force | recall **0.0**, alerts on 960 benign sources |
| Supervised ML vs static | ML catches **128** attack windows static misses; static catches **0** ML misses |
| Hybrid (ML ∪ novelty) | recall 0.93 but precision 0.44 — **novelty false-strongs hurt** |
| Incremental ARF vs periodic batch RF | ARF recall 0.94 / precision 0.77; batch recall 0.89 / precision 0.90, slightly cheaper — **no winner** |
| Self-learning, Friday (novel family) | **0.0 → 0.72** (23/32, CI [0.55, 0.84]; ≈0.68 over 10 seeds); old family retained only **with rehearsal** (erratum) |
| Self-learning, Tuesday SSH / FTP | SSH 1.0 → 1.0 (no change); FTP 0.83 → 0.73 (**slightly worse**) |
| Scan ceiling 15 ports/60 s vs real NMAP scan | catches the 997-port burst, but 13–57 % benign-source FPR over long horizons; **50–100 ports → detected at 0 benign FP** |

---

## 4. What is proven vs not proven

**Proven on the live lab:** infrastructure and recovery; verified enforcement and guards;
governed-lifecycle refusal; benign generalisation (A4, NV2).

**Proven offline on real recorded traffic (separate gate, audited):** brute-force behaviour
is learned (not leakage); the AI clearly beats static Suricata on brute force; self-learning
works on a genuinely novel family — with rehearsal; without it forgetting can be
catastrophic (`engineering/ERRATUM_FORGETTING.md`).

**Not proven (needs in-lab attack traffic):** live attack recall / false negatives;
independent value over static rules on the lab; live adaptation benefit; any live promotion;
general (family-independent) detection; transfer from CIC to the lab.

---

## 5. Limitations and how to fix each

| # | Limitation | Why it matters | How to fix it |
|---|---|---|---|
| 1 | **No live attack evidence** (gates B, E, parts of C/G blocked) | The central claim — detects real attacks in *this* lab — is unmeasured | The authorised team runs the scenarios from ATK01 per `TEAM_ATTACK_QUICKSTART.md` (3 test + 1 validation run per family). Then run `afwc dataset capture/validate`, `experiment evaluate --streaming`, `experiment supervised`. Cannot be done by the agent (safety boundary) |
| 2 | **Models are family-specific** (cross-family recall 0.11; Friday-trained 0.27) | Not a general attack detector | Add features that capture slow / bursty / distributed behaviour (longer horizons, per-destination fan-in, inter-arrival regularity, beacon periodicity); train on a *union* of families; evaluate with leave-one-family-out. Needs more labelled families (more CIC days, CSE-CIC-IDS2018, or team runs) |
| 3 | **Fixed scan ceiling mis-tuned** (15 ports/60 s) | High benign FPR over long horizons; low-and-slow scans evade a single 60 s window | Raise the ceiling toward 50–100 ports and evaluate 60 s **and** 300 s horizons together; **re-calibrate on lab benign** (CIC benign ≠ lab benign) before any change. Offline evidence is in `offline-cic-friday-2026-10-29/multihorizon-finding.md` |
| 4 | **Hybrid hurts precision** (novelty false-strongs) | Combining detectors made things worse | Use the supervised model as the primary signal; keep novelty as *evidence for human review*, not an OR-trigger; require agreement or calibrated thresholds before escalation |
| 5 | **Self-learning helps only novel families, and without rehearsal it can forget catastrophically** (10 seeds, held-out: old-family recall 0.78 ± 0.36, down to 0.08; with rehearsal 0.999; batch RF 0.92 ± 0.01) | "Learning improves detection" is conditional, and the earlier "no forgetting" claim was wrong (measured on training data) | **Keep rehearsal on (production default) and keep the 0.05 per-family recall-drop gate** — both are already in `ml/incremental.py`. See `engineering/ERRATUM_FORGETTING.md`. Also gate learning to examples the current model misses and keep an immutable anchor |
| 6 | **Offline results are CIC-domain** | Do not transfer to the lab | Re-train / re-calibrate on lab benign plus team attack captures; add domain-adaptation (per-feature normalisation) if mixing sources |
| 7 | **Every attack family here is ONE attacker session** — Tuesday has 3 independent attack bursts, Friday 4 (block-bootstrap recall CI Tuesday [0.62, 0.98], Friday [0.00, 0.59]) | Run-level n is 1 per family, so window-level CIs overstate certainty | Collect ≥ 2 independent runs per family (team runs, or CSE-CIC-IDS2018) and hold a whole run out; report burst-level CIs (done offline: `cic_robustness.py`) |
| 8 | **Brute-force signal is partly tool-shaped** ("no DNS + repetitive connections") | An evasive tool that resolves a name first could slip past | Test against several brute-force tools (Hydra, Medusa, Patator) and add jittered / slow variants; keep behaviour-only features |
| 9 | **Supervised classifier not wired into live shadow** | No live malicious-model telemetry | Deliberately not done: no lab-domain validation. Wire it into shadow **after** lab-domain training (limitation 6); keep enforcement off and promotion human-gated |
| 10 | **Limited visibility** (only ATTACK + USERS segments; TLS opaque; DMZ/APP/DB-allowed and intra-segment traffic unseen) | Lateral movement mostly invisible | pf blocks of server sources are already surfaced in shadow. Server-segment Suricata needs interface-aware flow tracking and a separate server detector — conditions listed in `engineering/SENSOR_EXPANSION_DECISION.md` §4 |
| 11 | **Low-and-slow / distributed web attacks below per-window minimum** (3 req/30 s) | Slow brute force may stay unassessed | Add per-account and per-source multi-horizon counters (A3 account-aware tracking already covers part of this); evaluate on slow-brute-force runs |
| 12 | **Colluding sources can vouch for each other** (≥ 4 similar tenured sources) | Residual poisoning risk | Cap per-cohort influence on admission; require provenance-verified labels only (already enforced for delayed labels); monitor challenger-vs-champion drift |
| 13 | **FW01 feed has no RELP** (OPNsense limitation) → ~100 s loss window | Brief telemetry gaps | Accept and document, or forward via a local RELP-capable relay; heartbeat already exposes gaps |
| 14 | ~~FW01 boot hook not upgrade-proof~~ **FIXED 2026-10-30** | — | The hook, the 1 GB swap file and the fstab line are now installed idempotently by `afw lab provision-fw` (`provision_fw.ensure_resources`, asset `lab/opnsense/afw-resources.syshook`), and **`lab/gns3/topology.yaml` FW01 RAM is 2560** (it still said 1536, so a rebuild would have reintroduced the OOM). 7 unit tests; verified live. After an OPNsense *firmware upgrade* re-run `afw lab provision-fw` |
| 15 | **Host is centrally managed and reboots unattended** | Lab goes down | `auto_start` enabled so it self-recovers; ask the host administrators to exclude `gns3server` from needrestart or to give a maintenance window |
| 16 | **All backups are on this one host** | Disk loss loses everything | **Encrypted off-host archives are now ready:** `scripts/make_offhost_backup.sh` builds two GnuPG AES-256 archives (code+data; secrets separate) in `~/afw-backups/offhost/` and proves they restore. **Copying them off this machine still needs your authorisation** (`scp` to a destination you choose, or `git push origin engineering-directive`); keep `~/.config/afw/backup.passphrase` somewhere different from the archives |
| 17 | **Legitimate users are scripted personas** | Real users behave differently; the AUTH thresholds were never approached | Validate with real users or recorded real-user traffic; add more persona archetypes |
| 18 | **Single host, self-signed PKI, not air-gapped** | Not production-grade | Real PKI / secrets vault, HA controller, scale tests (future work, not required for the degree) |
| 19 | **Consumed one-shot sets cannot be reused** | Prevents re-tuning on them | By design; use new data for any further tuning (already how A4 and NV2 were run) |
| 20 | **No model has been promoted** | Adaptation benefit not shown live | Needs a candidate that passes the gate, which needs attack-recall data (limitation 1) plus a human approver |

---

## 6. Acceptance gates

### Live GNS3 gates
| Gate | State | Basis |
|---|---|---|
| A Infrastructure | **MET** | lab, isolation 41/41, deploy, restart/OOM/self-recovery |
| D Enforcement | **MET** | read-back-verified actions, expiry, protected-address refusal |
| F Security and operations | **MET** | HTTPS API, mTLS telemetry, audited MCP, log rotation, recovery |
| C Adaptation | **PARTIAL** | live learning + rollback + live gate refusal; no promotion |
| G Academic defensibility | **PARTIAL** | methodology and honest results documented; team demo + in-lab evidence missing |
| B Detection | **BLOCKED** | no in-lab attack runs |
| E Independent value | **BLOCKED** | needs in-lab five-way comparison |

### Separated gate states (provenance never mixed — `engineering/GATE_STATES.md`)
Live GNS3 attack detection **BLOCKED** · Offline recorded-attack detection **MET (offline)** ·
Supervised learning **MET (offline), family-specific** · Unfamiliar-threat detection
**PARTIAL** · Safe adaptation / promotion **PARTIAL** · Network enforcement **MET**.
An offline result never advances the live gate.

---

## 7. Capability verdicts against the original vision

| Capability | Verdict |
|---|---|
| Learns useful behavioural patterns | **Yes** — benign (lab, proven); brute force (offline, audited); **family-specific** |
| Improves from independently verified new evidence | **Yes, offline, for novel families**; not universal; not shown live |
| Value beyond static rules | **Yes, decisively on brute force (0.90 vs 0.0); marginal on harder families**; not shown live |
| Network-wide coverage of attack categories | **Partial** — brute force good; scan threshold needs tuning; slow/distributed weak |
| Safe model governance | **Yes** — gate refuses live; nothing promoted |
| Real network enforcement | **Yes** (gate D MET) |

**Honest conclusion:** a fully working, safety-first, governed enforcement platform with
real but narrow and conditional self-learning value, validated by an unusually self-critical
methodology. It is **not** a finished, general, live-proven self-learning network firewall.

---

## 8. What is left, and when it finishes

**Done (≈ 80 %):** everything achievable without in-lab attack traffic.

**Remaining (≈ 20 %)** — one external dependency, then quick agent work:

1. **Team runs the attack scenarios** from ATK01 (≈ one afternoon). *Not the agent's step.*
2. Agent evaluates (≈ one day): five-way comparison → gates **B, E**; in-lab supervised and
   withheld-family evaluation; in-lab scan/SSH recall.
3. One human-approved promotion, if a candidate qualifies → gate **C**.
4. Team runs `FINAL_DEMO.md` → gate **G**.

No calendar date can be given: step 1 is not the agent's to take, so completion happens
whenever the team schedules it.

**Agent work that needs no attack traffic (optional, can improve the offline evidence):**
additional CIC / CSE-CIC-IDS2018 captures for more families and *repeat runs* of a family
(limitations 2, 7); richer slow/distributed features with leave-one-family-out evaluation
(limitation 2); fold the FW01 boot hook into `provision_fw` (limitation 14). Pushing the
branch needs the owner's say-so (limitation 16).

---

## 9. How to reproduce / where things are

| What | Where |
|---|---|
| Run everything verifiable | `scripts/final_verification.sh` |
| Recover the lab after a host reboot | `uv run afw lab start` (GNS3 `auto_start` should do it automatically) |
| Re-run offline CIC evaluation | `artifacts/evidence/offline-cic-2026-10-29/README.md` |
| Backups | `~/afw-backups/` (git bundle + portable tarball + sha256); `artifacts/evidence/backup-2026-10-29/` |
| Team attack runs | `docs/TEAM_ATTACK_QUICKSTART.md`, `docs/engineering/P3_TEAM_ATTACK_RUNBOOK.md` |

| Document | Purpose |
|---|---|
| `docs/STATUS_LIMITATIONS_FIXES.md` | **this file** |
| `docs/FINAL_REPORT.md` | demonstrated / failed / blocked / vision verdict |
| `docs/ARCHITECTURE_VS_GOALS.md` | architecture vs original goals |
| `docs/engineering/OFFLINE_CIC_AUDIT.md` | label / leakage audit and corrections |
| `docs/engineering/OFFLINE_INDEPENDENCE.md` | cross-dataset findings |
| `docs/engineering/GATE_STATES.md` | separated gate states |
| `docs/engineering/REVISED_ASSESSMENT.md` | six-capability assessment |
| `docs/RESULTS.md`, `docs/VALIDATION_MATRIX.md` | results and evidence matrix |
| `artifacts/evidence/` | every measurement (`a3-`, `a4-`, `nv1-`, `nv2-`, `offline-cic-`, `offline-cic-friday-`, `fw01-oom-fix-`, `net-dns-`, `backup-`, `live-governance-`, …) |
