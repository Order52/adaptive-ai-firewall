# Phase 0 — Independent engineering audit (2026-10-27)

_Auditor: Claude (treating all earlier Claude-session work as untrusted). Scope: the
repository, the host, and the live GNS3 lab. Evidence directory:
`artifacts/evidence/phase0-2026-10-27/`. This document stands on its own; it does not
rely on conversation history._

## 0. Identity and recovery baseline

| Item | Value |
|---|---|
| Repository | `~/uot/ai-adaptive-firewall`, remote `git@github.com:Order52/adaptive-ai-firewall.git` |
| Audited commit | `6875795` (status-report docs on top of `eb22909`) |
| Baseline tag | **`baseline-2026-10-27`** (pushed) |
| Working branch | **`engineering-directive`** (all directive work happens here) |
| Host | 20 vCPU (i7-13650HX), 15 GiB RAM + 4 GiB swap, 200 GB root (158 GB free) |
| GNS3 | gns3server running; lab powered off at audit start, started for live checks |
| Non-git state | VM disks (GNS3 project), controller SQLite (`/var/lib/afw` on CTRL01), model artifacts, datasets, Postgres volume on DB01, secrets in `~/.config/afw/`. Host backups in `~/afw-backups/` (latest 2026-10-21). A fresh Phase 0 backup is listed in §7. |

## 1. Baseline checks, re-run today (not copied from older reports)

| Check | Result | Evidence |
|---|---|---|
| `pytest` (unit + integration) | **57 passed, 9 skipped** (the lab tests need `AFW_LAB=1`) | `pytest.txt` |
| `mypy` strict (`src`) | **clean, 81 files** | `mypy.txt` |
| `afw config-check` | OK: 6 zones, 1 app | `config-check.txt` |
| `ruff check` + `ruff format --check` (whole repo) | **FAIL: 13 errors**, all in `docs/figures/make_figures.py`. The earlier "ruff clean" claim was wrong for the whole repo. | `ruff.txt` |
| `pip-audit` on locked runtime deps | **1 vulnerable package**: `certifi 2026.7.22` (PYSEC-2026-4320, fixed in 2026.10.19) | `pip-audit.txt` |
| Secret scan of tracked files | No private keys or tokens; no `.pem`, `.key`, `.sqlite`, `.qcow2` or token files tracked | grep in this audit |
| Live isolation and lab acceptance | See §7 (re-run on the live lab) | |

## 2. Component inventory (verified)

**Lab (15 GNS3 nodes, `lab/gns3/topology.yaml`):**
- **Compute nodes:**
  - FW01 OPNsense 26.7 with 7 NICs
  - CTRL01 controller, 10.77.50.10
  - DESK01 XFCE desktop, 10.77.50.20
  - WAF01 nginx + ModSecurity with CRS 4.25, 10.77.30.10
  - APP01 rental app, 10.77.40.10:8000
  - DB01 PostgreSQL 16, 10.77.60.10
  - USR01 client, 10.77.20.10 / .250
  - ATK01 client, 10.77.10.10 / .250
- **Switches (6):** SW-ATTACK, SW-USERS, SW-DMZ, SW-APP, SW-DB, SW-MGMT
- **Uplinks (2):** HOST-MGMT (host TAP), MAINT-NAT

**Controller code (`src/afw`, about 9.9k lines, typed):**

| Package | Responsibility |
|---|---|
| `telemetry/` | TCP syslog receiver (sender allowlist, bounded queue); parsers for WAF access/audit, app events and Suricata EVE; request correlator (WAF↔app join by request id) |
| `features/` | 30 s / 5 s-hop sliding windows per source IP; 13 behavioural features |
| `ml/` | detectors (robust-z, Isolation Forest, River Half-Space-Trees); training with validation-set thresholds at a 1% FPR budget; artifact registry (sha256); dataset manifests and labels; M0/M1/M2 replay runner |
| `correlation/` | evidence scoring (behaviour/WAF/auth/IDS/history), capped additive risk score, corroboration |
| `policy/` | decision engine, typed validator (protected addresses, bounds), policy service with an explicit state machine (PROPOSED…ENFORCED/EXPIRED/ROLLED_BACK/FAILED/UNKNOWN) |
| `enforcement/` | OPNsense alias/state API adapter, WAF helper adapter, probe verifier, memory backend |
| `profiling/` | profile builder (anti-poisoning source caps), drift monitor (ADWIN per feature, new endpoints/versions), source reputation |
| `services/` | runtime loop, learning/promotion use cases, explanations |
| `api/`, `dashboard/`, `mcp/` | FastAPI with role-scoped bearer tokens; static dashboard; MCP stdio server (26 tools) calling the API |
| `lab/` | GNS3 build/layout, seeds, OPNsense config transform, isolation verifier, secrets |

**Data path (as implemented):**

```
WAF/app/Suricata → rsyslog omfwd (TCP, in-memory LinkedList queue, infinite retry)
  → CTRL01 SyslogReceiver (IP allowlist, bounded queue, drop+count)
  → RequestCorrelator (join WAF+app by request id)
  → SlidingWindows → InferenceEngine (robust + IF)
  → CorrelationEngine → DecisionEngine → PolicyService
  → OPNsense / WAF → read-back + probe verification
```

## 3. Critical findings

Severity: 🔴 must fix before any claim relies on it · 🟠 important · 🟢 minor.

### 3.1 AI / adaptation: the system does not currently learn online (🔴)

What the code actually does:
- Live detection uses robust-z and Isolation Forest only (`Strategy.ML`). Half-Space-Trees is batch-trained and registered, but **is never scored live and `learn_one` is never called at runtime** (`grep learn_one` matches only the HST detector itself). The docs call HST a "shadow learner that keeps learning". **That is false.**
- "Adaptation" means: an operator calls `build_candidate`, which takes stored observations from a time range, rebuilds a profile and **retrains all detectors from scratch**, then runs a gate and waits for human promotion. That is periodic batch retraining with gating. It is useful and safe, but it is **not incremental learning**, has no prequential evaluation and no persisted challenger state.
- The gate includes `attack_recall_regression`, which **always fails without labelled attack data**. So in the current state **no candidate can ever be promoted**. That is safe, but it means the adaptive lifecycle has never completed end-to-end on real data.
- Drift monitoring (ADWIN per feature, new endpoints/versions, FP feedback) is **unsupervised feature drift**. It cannot by itself show concept drift. The docs mostly respect this, but no drift report has ever been shown to lead to a promoted model.
- `SourceReputation` (IDS/WAF/auth taint) lives **only in memory** and is lost on controller restart. After a restart, a previously tainted source can contribute to the shadow stream. `build_candidate` still re-excludes WAF-hit sources from stored observations, but not IDS-tainted ones.
- Only one model family is registered per profile version. There is no explicit **champion/challenger pair evaluated on the same live stream (shadow inference)**, and no automatic rollback trigger.

Verdict: **the "genuinely adaptive" requirement (Gate C) is NOT met.** The existing building blocks (River HST, ADWIN, gate, versioned registry, reputation filter) are sound foundations and should be preserved and completed, not replaced.

### 3.2 Correlation: evidence independence is violated (🔴, safety)

`CorrelationEngine.assess` counts `AUTH` and `BEHAVIOR` (and `WAF` and `BEHAVIOR`) as independent corroborating categories. They are often derived from **the same underlying requests**:
- A burst of failed logins produces AUTH evidence (from `auth_failures`). The behaviour detectors fire because `auth_fail_frac`, `login_rate` and `distinct_usernames` are features computed **from those same events**.
- WAF-blocked requests return 403, which drives `client_err_frac`, so a single CRS hit stream can yield both WAF and behaviour evidence.

The "≥2 independent categories before a block" invariant (ADR-013) can therefore be satisfied by **one event stream**. This is a correctness and safety defect: it can authorise blocks on weaker evidence than documented. **Fix:** give each evidence item an explicit provenance (which telemetry families it was derived from). Behaviour evidence then counts as independent only if its contributing features are not derived from the same families as the other evidence.

### 3.3 Telemetry (🟠)
- Single detection view: **per-source-IP HTTP windows only**. IDS-only sources (scans, non-HTTP) get no assessment. There is no account-, session- or endpoint-level view and no slow (multi-hour) horizon.
- Transport is plaintext TCP syslog, authenticated only by sender IP. It is inside segmented zones and SSH-free, but there is **no integrity protection**. A compromised WAF/APP host can forge telemetry (this belongs in the threat model).
- rsyslog uses in-memory queues. Events are **lost if the sender reboots while CTRL01 is down**; the controller queue drops on overflow, which is counted and marks evidence "degraded" (good).
- Events carry `event_id` and `observed_at` but **no schema version and no receipt time**. Late or replayed lines are not explicitly deduplicated in the ingest path.

### 3.4 Evaluation (🔴 for the research claim)
- **No labelled attack data exists.** Attack recall, detection delay under attack, containment success, and M0–M2 comparisons under attack are all unmeasured.
- Benign results are real but small: 6 sources, 361 training windows from scripted personas. Windows overlap (30 s windows on a 5 s hop), so **the effective number of independent samples is much smaller than the window count**. FPR confidence intervals must be computed on non-overlapping units (runs or sources), not raw windows.
- There is no repeated-run variance and no seeds/CI reporting.

### 3.5 Engineering hygiene (🟢 / 🟠)
- ruff fails (figures script); certifi CVE.
- `docs/` has several overlapping status sources (IMPLEMENTATION_STATUS, MASTER_COMPLETION_PLAN, PROJECT_STATUS_AND_HANDOFF, PROJECT_STATUS_REPORT, SESSION_*). These need consolidating into one `PROJECT_STATUS.md`.
- No property-based tests (CIDR/direction/protected-address/state-machine logic is a good fit).
- The API defaults to HTTP (justified by the SSH tunnel). The lab now has Internet egress, so guest compromise has an exfiltration path. This must be in the threat model.

### 3.6 What is sound and should be preserved
- **Enforcement path:**
  - typed policy validator and protected-address refusal
  - explicit policy state machine
  - read-back plus probe verification
  - watchdog fail-safe
  - least-privilege OPNsense API user
- **Topology:**
  - 3-tier topology with an isolation verifier (35 checks)
  - reproducible bake/build/provision/deploy
- **Attribution:** WAF↔app request-id correlation and true-client-IP attribution.
- **Model handling:**
  - versioned profiles and models with sha256 artifacts
  - validation-only thresholding
  - attack data never used for fitting
- **MCP:** goes through the same API, validator and audit path; no shell tool.

## 4. Preserve / refactor / replace / build

| Subsystem | Decision | Reason |
|---|---|---|
| GNS3 lab, OPNsense, Suricata, WAF, app, DB | **Preserve** | Real and verified; isolation tested |
| Enforcement and policy state machine | **Preserve**, add property tests | Correct design; needs adversarial tests |
| Correlation engine | **Refactor** | Provenance-aware corroboration (§3.2) |
| Telemetry ingest | **Refactor + extend** | Envelope (schema version, receipt time), dedup, IDS-only/network view, durable sender queues |
| Detectors (robust, IF, HST) | **Preserve** | Sound baselines (M1, M2) and the online base (M3) |
| Learning lifecycle | **Build on existing** | Real online challenger (prequential HST), persisted state, champion/challenger shadow inference, promotion/rollback policy |
| Source reputation | **Refactor** | Persist taint; provenance-tracked training eligibility |
| Evaluation runner | **Extend** | M3/M4 arms, run-level CIs, seeds, scenario harness consuming team-run ground truth |
| GeoIP | **Build** | Real country DB (DB-IP Lite, CC-BY), directional OPNsense aliases |
| Dashboard | **Extend** | Champion/challenger, drift, incident timeline |
| Docs | **Consolidate** | One status, one architecture, validation matrix |

No wholesale rewrite is justified. Every defect above is fixable inside the current hexagonal structure.

## 5. Target architecture (summary; see ADRs as they are written)

**Detection path:**

```
Sensors → Ingest (envelope, dedup, bounded spool)
  → Normalize → Feature views [source-IP HTTP | account | IDS/network]
  → Detectors [M1 robust | M2 IF (frozen) | M3 HST champion]
  → Correlation (provenance-aware)
  → Decision → Validator (invariants) → Enforcement → Verify → Audit
```

**Learning path** (separate process lane, never touches enforcement directly):

```
eligible windows (persisted reputation + provenance, quarantine)
  → challenger HST: prequential (score-then-learn), state checkpoints
  → shadow inference alongside champion on live stream
  → drift reports (feature / score / workload / telemetry-health, kept distinct)
  → evaluation policy (benign FPR, sensitive-feature guard, source-share cap,
    independent attack benchmark when available)
  → promote (human, or pre-authorised bounded auto) / reject
  → monitor → automatic rollback on regression
```

## 6. Prioritised roadmap (dependency-ordered)

Each milestone ends with tests, evidence and doc updates. Status lives in `docs/PROJECT_STATUS.md` once consolidated.

| # | Milestone | Depends on | Acceptance criteria |
|---|---|---|---|
| **M0** | Hygiene and baseline | — | ruff clean repo-wide; certifi bumped; Phase 0 backup of controller DB, models and datasets on the host |
| **M1** | Provenance-aware corroboration (§3.2) | M0 | Evidence items carry provenance; auth-only and WAF-only streams can no longer reach 2 categories; regression tests for both; existing tests pass; ADR |
| **M2** | Real online challenger (Gate C core) | M1 | HST challenger fed only from eligible windows; prequential score-then-learn records; state checkpoint and restore; a measurable state change proven by replay; shadow scores alongside the champion; persisted reputation |
| **M3** | Champion/challenger lifecycle | M2 | Immutable versions, promotion policy (human by default, bounded auto option), automatic rollback on a regression signal, audit records; tests for promote/reject/rollback |
| **M4** | Adaptation experiments (benign shift, poisoning, regression) | M3 | Reproducible scripts on recorded lab traffic: legitimate workload shift → challenger adapts and lowers FPR vs frozen; concentrated poisoning stays quarantined; injected regression → rollback. Run-level CIs |
| **M5** | Telemetry v2 (envelope, dedup, IDS-only view) | M1 | Schema version and receipt time; duplicate lines ignored; IDS-only sources assessed (never blocked on IDS alone) |
| **M6** | Attack evaluation harness | M5 | Scenario registry, ground-truth log, kill switch, M0–M4 replay with CIs. **Attack traffic itself is executed by the team** with standard tools against lab targets (see §8) |
| **M7** | Real GeoIP directional policy | M0 | Country DB with freshness; inbound/outbound/both on OPNsense with read-back; preview and audit via MCP |
| **M8** | Dashboard: adaptation, incidents | M3 | Champion/challenger, drift, incident timeline; provenance on every chart |
| **M9** | Docs consolidation and validation matrix | all | Single sources of truth (§14 of the directive) |

## 7. Live-lab verification (re-run 2026-10-27)

| Claim | Re-run result | Evidence |
|---|---|---|
| 35 isolation checks pass | **Reproduced: 35/35** (incl. DB isolation, no WAF bypass, Internet egress allowed) | `lab-verify.txt` |
| 9 live-lab acceptance tests pass | **Reproduced: 9 passed** (enforcement, safety, IDS path, MCP) | `pytest-lab.txt` |
| Lab boots from power-off | **Reproduced**: 8 VMs started, controller active within ~3 min | `lab-start.txt` |
| Controller DB intact | **Reproduced**: online backup `integrity_check = ok` | §0 backup |
| Live 0-FP inference, 60-min soak, train/val/test FPR 0 | **Historical, not re-run today** (needs a traffic run; scheduled with M4 baselines) | `artifacts/evidence/*-2026-10-1[7-9]*`, `soak-2026-10-20.md` |

**Phase 0 backup** (host, outside git): `~/afw-backups/phase0-20261027T171307Z/` contains
- `afw-state.tgz`: online SQLite backup, datasets, models
- `rental-pg.sql.gz`: `pg_dump` of the rental DB
- `SHA256SUMS`

Restore procedure: stop `afw-controller`, extract into `/var/lib/afw` (owner `afwctl`), remove stale `-wal`/`-shm` files, start the controller. For Postgres: `zcat … | docker exec -i <c> psql`.

## 8. Blockers and constraints (explicit)

- **Attack traffic generation.** Earlier sessions established that the assistant does not author attack tooling. The team runs standard tools (e.g. hydra, sqlmap, nmap, nikto) **from ATK01 against lab-owned targets only**. The harness (M6) records ground truth, enforces the target allowlist and kill switch, and evaluates the results. Until that data exists, Gates B (labelled attack evaluation) and E remain **FAILED/INCOMPLETE** and are reported as such.
- **GeoIP DB download** needs the user's consent (a third-party download), requested at M7.
