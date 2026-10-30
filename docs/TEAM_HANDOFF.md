# AI-Adaptive-Firewall — team handoff: from zero to where we are now

**Read this first.** It explains the whole project to someone who has never seen it: what it is,
how it works, what has been built and measured, what is *not* finished, what is wrong or weak, and
exactly what is left and who does it. It is written to be read top to bottom, but each section
stands alone.

*Written 2026-10-30. Branch `engineering-directive`, 183 commits, 96 of them not yet pushed to
GitHub. Repository: `~/uot/ai-adaptive-firewall` on the lab host. Lab is healthy and in
**monitor mode** (it watches and proposes, it does not block anything).*

> **Who wrote this and how to trust it.** Most of the engineering and analysis was done by an AI
> coding agent (Claude Code) working under the owner's direction. Every number in this document
> has an evidence file under `artifacts/evidence/`, and the agent re-checked its own work and
> **corrected three of its own earlier claims** (see §7.3) — so where this document is modest, that
> is on purpose. The agent **does not generate attack traffic**; that is the team's job (§9).

---

## 0. The 60-second version

- We built an **adaptive firewall**: software that watches traffic to a web application, scores how
  suspicious each source is, and — when allowed — blocks or slows it, then **learns from new
  evidence** without being retrained from scratch.
- It runs on a **real virtual lab** (8 VMs in GNS3). The engineering works and is verified:
  isolation 41/41, live tests 14/14, 384 unit tests, blocks are verified by reading them back from
  the firewall, models can be rolled back.
- The AI part **works on recorded attack data** (public CIC-IDS2017 captures analysed offline):
  it detects brute-force-style attacks about **twice as well as the standard Suricata rules**, and
  it can learn a new attack family. But the models are **specific to each attack family**, and the
  learning needs safeguards or it forgets.
- **What nobody has proven yet is that it detects attacks *in our own lab*.** That needs attack
  traffic run inside the lab, and **the team has to run it.** It is about one afternoon of work, and
  it is the single thing standing between "very good engineering project" and "evaluated system".
- Unfamiliar names (P6, A4, NV2, ADR, "predeclared", "Phase E")? They are decoded in §14.1; the datasets, the traffic generator, rebuilding the lab and a reading order are in §14.
- **Please do not turn on blocking (enforce mode) casually.** The model currently in charge flags far
  too many normal users (§8, limitation 1).

---

## 1. The idea, in plain language

A normal firewall follows fixed rules ("block this address, allow that port"). Fixed rules cannot
notice an attacker who stays within the rules but *behaves* strangely — for example, a script that
tries 500 passwords, or a scanner that probes 1,000 ports slowly. Our system tries to notice
**behaviour**:

1. It watches how each source address behaves over short time windows (how fast, how many
   different pages, how many failed logins, how many different ports…).
2. It compares that behaviour with what **normal users** do, learned from real lab traffic.
3. It combines several **independent** signals (the web firewall, the intrusion detector, login
   failures, history) — one odd signal alone is never enough to block.
4. If it decides to act, it applies a block or a rate limit on the real firewall, **checks it took
   effect**, and removes it automatically after a time.
5. When new, confirmed attack examples appear, a **challenger** copy of the model learns from them
   in the background. A person decides whether the challenger replaces the current model; if it
   misbehaves afterwards, the system rolls back automatically.

"Adaptive" means step 5. "Safe" means everything wrapped around it: protected addresses can never be
blocked, the challenger is tested on data it has never seen, a human approves promotion, and the
whole thing starts in monitor mode.

---

## 2. The lab

Eight virtual machines in GNS3, separated into network zones by a firewall (FW01). Traffic between
zones is only possible where the firewall allows it.

```
                 Internet (egress allowed)
                         |
   ATK01 (attack zone) --+--  FW01 OPNsense  --+-- USR01 (legitimate users)
   10.77.10.10           |   (every zone's     |   10.77.20.10
                         |    gateway, IDS,    |
                         |    pf, Suricata)    +-- WAF01 (DMZ)  10.77.30.10  <-- the ONLY path in
                         |                     +-- APP01 (APP)  10.77.40.10
                         |                     +-- DB01  (DB)   10.77.60.10
                         |                     +-- CTRL01 (MGMT) 10.77.50.10   the controller
                         |                         DESK01 (MGMT) 10.77.50.20   operator desktop
```

| VM | Address | What it does |
|---|---|---|
| **FW01** | `.1` in each zone | OPNsense firewall. Enforces zone separation, holds the dynamic block lists, runs **Suricata** (intrusion detector) and exports network metadata. 2560 MB RAM + 1 GB swap |
| **WAF01** | 10.77.30.10 | Reverse proxy + web application firewall. Everything reaching the app goes through it (HTTPS :443) |
| **APP01** | 10.77.40.10 | The protected application — a car-rental website |
| **DB01** | 10.77.60.10 | The application's PostgreSQL database; only APP01 may reach it |
| **CTRL01** | 10.77.50.10 | **The brain.** Runs the controller, models, API and dashboard |
| **USR01** | 10.77.20.10 | Generates *legitimate* user traffic (scripted "personas") |
| **ATK01** | 10.77.10.10 | The attack machine. **Only the team uses it**, only against WAF01 |
| **DESK01** | 10.77.50.20 | Operator desktop (graphical) |

Two safety facts about the network that matter for the team:
- From ATK01 the **only** reachable service is WAF01 :443. Ports 22/80/3306 on WAF01 are deliberately
  blocked (they exist so port-scan runs have something to probe). Management (10.77.50.0/24) and
  the database (10.77.60.0/24) **can never be attack targets**; the scenario tool refuses them.
- `afw lab verify` checks 41 such rules ("clients cannot bypass the WAF", "DB reachable only from
  APP", …). It should always print **41/41 checks passed**.

---

## 3. How the software works

### 3.1 The pipeline (in order)
1. **Sensors send telemetry to CTRL01 over mutually-authenticated TLS.** WAF01/APP01 send web and
   app logs (RELP, port 5516); FW01 sends Suricata alerts and flow/DNS/TLS/SSH metadata (syslog-TLS,
   port 5514). Each also sends a **heartbeat**; if one goes quiet the controller notices and
   pauses automatic enforcement.
2. **Windows.** The controller groups requests per source address into 30-second windows and
   computes about 13 behaviour numbers (request rate, route entropy, error fractions, login rate,
   failed-login fraction, distinct usernames, …). A parallel **network path** builds 60 s and 300 s
   windows from flow/DNS/SSH metadata (28 numbers) for traffic that is *not* ordinary web use.
3. **Detectors** score each window. *Robust statistics* and *Isolation Forest* are in charge;
   *Half-Space-Trees* runs in **shadow** (scores but changes nothing).
4. **Evidence.** The score is combined with independent evidence categories — AUTH (login abuse),
   WAF (web-firewall rules), IDS (Suricata), HISTORY — into a 0–100 score (an *evidence score*, not a
   probability). Rate-limit around 45, block around 65. **A block needs at least two independent
   categories**; an anomaly alone, or IDS alone, never blocks.
5. **Safety validation.** Protected addresses (management, DB, firewall, WAF/APP networks) can
   never be acted on. An address used by ≥3 different accounts in the last hour is "shared"; a block
   for it becomes a human-approved rate limit.
6. **Enforcement and verification.** Blocks go to FW01 (OPNsense alias) or the WAF (deny / rate
   limit / login-only throttle). The controller **reads the rule back** and only then marks it
   *enforced*. Everything expires automatically.

### 3.2 Modes
- **monitor** (current): everything is scored and *proposed*; nothing is applied. Use this for all
  attack runs.
- **enforce**: proposals are applied. Do not use it with the current model (§8, #1).

### 3.3 The learning lifecycle (champion / challenger)
```
 trusted model ("champion")  ── scores live traffic, drives decisions
        │
        └─ copy learns in the background ("challenger", SHADOW only, never affects traffic)
              learns only from authenticated, untainted, corroborated NORMAL windows
        │
   promotion gate (automatic checks on data the challenger never learned from)
        │  must pass: enough learning, not worse on normal traffic, no regression on known
        │  attacks, no loss of sensitivity …
   human approves ──► probation (watched) ──► auto-rollback if it misbehaves
```
Every step is recorded; checkpoints carry sha256 and provenance; a corrupt model can never be
activated. **Today the gate correctly refuses** every candidate, mainly because it has no labelled
attack data to test recall — which is what the team's attack runs will supply.

### 3.4 Login protection (A3/A4)
Failed logins are tracked **per account and per address**. Heavy guessing gets a **login-only**
throttle then a login-only deny — never a block of the whole site — and an address shared by many
legitimate accounts (a household, an office) is not punished for it.

---

## 4. Map of the repository

| Folder | What is in it |
|---|---|
| `src/afw/` | The product. `telemetry/` (parsers, receiver), `features/` (windows), `ml/` (detectors, classifiers, lifecycle, evaluation), `correlation/` (evidence), `policy/` + `enforcement/` (decide + apply), `api/` + `dashboard/` (HTTPS API, web UI), `lab/` (build/provision/verify the lab, scenario harness), `mcp/` (AI-assistant interface), `cli.py` (the `afw` command) |
| `tests/` | `unit/` and `integration/` (run anywhere); `lab/` (needs the live lab, 14 tests) |
| `lab/` | Ansible roles, GNS3 topology, image-baking scripts, OPNsense assets (watchdog, FW01 boot hook) |
| `config/` | `lab.yaml` (the controller's config), `scenarios.yaml` (the attack-run registry and allow-list) |
| `traffic/` | `benign_personas.py` — generates *legitimate* user traffic. **There is no attack generator in this project and there never will be** |
| `scripts/` | `final_verification.sh` (run everything verifiable), `make_offhost_backup.sh`, `set_vm_passwords.sh`, `archive_datasets.sh` |
| `docs/` | Design, results and runbooks. Start with this file, then `FULL_STATUS_AND_ROADMAP.md`, `TEAM_ATTACK_QUICKSTART.md` |
| `artifacts/evidence/` | **Every measurement**, by date/topic (36 folders). If a number is quoted anywhere, its raw file is here |

Key documents: `docs/ARCHITECTURE.md` (design), `docs/ARCHITECTURE_DECISIONS.md` (44 decisions and
why), `docs/RESULTS.md`, `docs/VALIDATION_MATRIX.md` (every acceptance criterion → evidence),
`docs/engineering/GATE_STATES.md`, `docs/engineering/ERRATUM_*.md` (corrections).

---

## 5. How we got here (short history)

| When | What happened |
|---|---|
| Before 10-27 | Lab built; first detectors, correlation, enforcement, dashboard, MCP; real benign baseline and soak test |
| 10-27 | Milestones M0–M9: online learning, champion/challenger gate with probation and rollback, drift experiments, telemetry hardening, attack-evaluation harness, real GeoIP |
| 10-28 | Hardening (mTLS, HTTPS, RELP, heartbeats); network metadata and novelty detector; supervised classifier + incremental learner (tested on synthetic data); model-selection experiments P1–P7 (**no eligible model**) |
| 10-29 | Login controls A3 (final test **failed** on households) → A4 (**passed**); network novelty NV1 (**failed**) → NV2 (**passed**); FW01 out-of-memory incident found and fixed; first offline evaluation on recorded attack traffic |
| 10-29/30 | Independent audits, three CIC captures, self-learning studies, **three self-corrections**, FW01 fix made durable, encrypted backups, VM logins simplified, this handoff |

---

## 6. What is finished, what is partly done, what is not done

**Finished and verified**
- The lab, its isolation (41/41), reproducible deployment, restart and out-of-memory recovery.
- Telemetry with integrity and loss-free delivery under controlled faults; heartbeats.
- Enforcement with read-back verification, expiry, protected-address refusal, shared-address guard.
- The governed model lifecycle, including a live demonstration that the gate **refuses** an
  unqualified model and that rollback restores the previous model exactly.
- Login protection that does not lock out legitimate users (0 of 2,791 legitimate logins refused).
- Network-novelty detector with a measured low false-alarm rate on unseen normal users.
- Dashboard (14+ panels on live data), API, MCP interface, automated verification script.
- Backups: verified git bundle and **encrypted** off-host archives (not yet copied off the machine).

**Partly done**
- *Adaptation (gate C):* learning, shadowing, gate and rollback all work; nothing has been promoted
  because no candidate qualifies without attack data.
- *Academic defensibility (gate G):* methods and honest results are documented; the team
  demonstration and in-lab evidence are missing.
- *Network visibility:* flows are seen on the attack and user segments; server-side traffic that the
  firewall allows is not (§8, #10).

**Not done — and why**
- **Live attack detection in the lab (gate B)** and **value over static rules in the lab (gate E):**
  need attack runs from ATK01 → **the team** (§9).
- The supervised classifier is **not** wired into live shadow: no lab-domain data to validate it yet.
- No model promoted; no enforce-mode evaluation.

Of the seven live acceptance gates: **3 met (A, D, F), 2 partial (C, G), 2 blocked (B, E).**

---

## 7. Results, explained

### 7.1 On the live lab
| Test | Result |
|---|---|
| Isolation rules | 41 / 41 |
| Live lab tests | 14 / 14 |
| Unit + integration tests | 384 passed |
| Login protection on unseen users, incl. households (A4) | 0.0 false-positive rate; 0 of 2,791 logins refused |
| Network novelty on 22 unseen users (NV2) | unfamiliar-traffic rate 0.0059 [0.0016, 0.0115] |
| FW01 under 54 simulated users for 10 min | Suricata stable, memory flat, swap barely used |

### 7.2 On recorded attack traffic (offline; NOT the live lab)
We downloaded three public captures (CIC-IDS2017: Tuesday, Thursday, Friday), replayed them through
Suricata **offline** (nothing was sent on any network) and ran our feature pipeline and models on the
results. Attackers are labelled by IP; hosts compromised mid-capture are excluded.

| Question | Answer |
|---|---|
| Does the model detect brute-force attacks? | **Yes.** Recall 0.85 (≈0.92 with behaviour-only features), **0 false positives in 13,499 normal windows** — but only **3 independent attack bursts**, so the honest interval is wide: [0.62, 0.98] |
| Is it learning behaviour or just the attacker's address/port? | **Behaviour.** Using only identity features (ports/hosts) recall is 0.00; behaviour-only 0.92 |
| Does it transfer to a different day/attack? | **Partly.** Trained on Tuesday+Friday it detects 0.54 of Thursday's web attacks (0.88 of the morning ones) at 0 false positives. From Tuesday alone to Friday: 0.11 → **family-specific** |
| Does it beat standard Suricata rules? | **About 2× on brute-force-style activity** (0.90 vs 0.43; 0.88 vs 0.28), at near-zero false positives, and the two catch *different* windows (together 0.91 on Thursday morning). On the hard families both are weak |
| Can it learn a new attack family? | **Yes, with limits:** recall on a new family rose from ≈0.5 to ≈0.9 — **but only if old examples are replayed ("rehearsal")**; without that it can forget old attacks badly |
| Is online learning better than periodic retraining? | **No evidence for that.** Batch retraining got within ~6 points at ~16× fewer false positives and ~15× less compute |
| Scan detection | The fixed "15 ports / 60 s" limit is too low; ~50–100 ports works offline with no benign false positives — **must be re-checked on lab traffic** |

### 7.3 Our three self-corrections (important for honesty)
1. **"No forgetting" was wrong.** It had been measured on training data. On held-out data the learner
   without rehearsal forgets (old-family recall 0.78 ± 0.36, down to 0.08). The production learner
   already replays old examples by default and its gate rejects a drop over 0.05.
   → `docs/engineering/ERRATUM_FORGETTING.md`
2. **"Standard Suricata detects 0.0" was wrong.** Our first setup put the attacker inside the
   "home network", so many rules could not fire. With a fair setup the AI's advantage is real but
   about half what we first said. → `docs/engineering/ERRATUM_STATIC_BASELINE.md`
3. **Confidence intervals were too tight.** Each attack family is one attacker session, so there are
   only 3–7 independent examples per family. Wider, honest intervals are now used.

---

## 8. Limitations and how to fix them

| # | Limitation | How to fix | Who / effort |
|---|---|---|---|
| 1 | **The current live model (v2) flags most new users as anomalous** (≈84 % of windows on unseen users in tests). Fine for monitor mode, **not safe for enforce mode** | A candidate that passes the gate, which needs attack data (#2) plus lab-domain benign data; until then stay in monitor mode | Team + agent |
| 2 | **No in-lab attack evidence** (gates B, E) | Run the attack scenarios (§9), then the evaluation commands | **Team**, ~1 afternoon + ~1 day |
| 3 | **Models are family-specific** (0.11 across families) | Features for slow/bursty/distributed behaviour; train on several families; leave-one-family-out testing; needs more labelled families | Agent, days |
| 4 | **Tiny independent sample** (3–7 bursts per family) | ≥2 independent runs per family (team runs, or another public dataset); hold a whole run out | Team / agent |
| 5 | **Incremental learning forgets without rehearsal; helps only for genuinely new families** | Keep rehearsal on and the per-family recall-drop gate (already the default) | Already in code |
| 6 | **Scan limit mis-tuned** | Calibrate on lab benign traffic (needs no attack traffic), then raise toward 50–100 ports and check two time horizons | Agent, can start now |
| 7 | **Offline results are on CIC data, not our lab** | Train/calibrate on lab benign + team attack captures | Needs #2 |
| 8 | **Supervised classifier not in live shadow** | Wire it into shadow after #7; keep enforcement off, promotion human-gated | After #7 |
| 9 | **Hybrid (ML OR novelty) hurts precision** | Use ML as the primary signal; keep novelty as a hint for humans | Agent, small |
| 10 | **Limited visibility:** firewall sees attack + user segments; TLS content is opaque; server-to-server traffic the firewall allows is unseen | pf blocks of server sources are already shown; deeper inspection needs a separate design (`engineering/SENSOR_EXPANSION_DECISION.md`) | Future |
| 11 | **Slow/distributed web attacks fall below the per-window minimum** | Longer-horizon per-account/per-source counters | Agent |
| 12 | **Colluding sources can vouch for each other; label-flip poisoning is only caught by the test-set gate** | Cap each group's influence; require provenance-verified labels | Agent |
| 13 | **FW01 feed has no RELP** (~100 s possible loss) | Accept or add a relay; heartbeats expose gaps | Optional |
| 14 | **After an OPNsense firmware upgrade the boot hook may be lost** | Re-run `uv run afw lab provision-fw` (safe to repeat) | Anyone, 1 command |
| 15 | **The host reboots unattended** (centrally managed) | GNS3 `auto_start` is on, so the lab restarts itself; else `uv run afw lab start`. Ask the host admins to exclude `gns3server` from auto-restarts | Owner / admins |
| 16 | **All backups are on one machine** | Copy the encrypted archives off it (owner approval needed) | **Owner** |
| 17 | **Simulated users are scripted** | Validate against recorded real-user traffic | Future |
| 18 | **VM passwords are deliberately weak** (owner's choice for a closed lab) | `scripts/set_vm_passwords.sh --lock` before any shared use | Owner |
| 19 | **Single host, self-signed certificates, not air-gapped** | Real PKI, HA controller, scale tests — beyond the degree | Future |
| 20 | **Test sets used once cannot be reused** | By design; new data for any further tuning | — |

---

## 9. What is left, and exactly what the team does

### 9.1 The one blocking job: run the attack scenarios
Everything else is waiting on this. The harness records ground truth, enforces limits and gives you
an emergency stop; **you supply the attack tools and run them from ATK01.** Tools already on ATK01
(installed, never run): `nmap`, `hydra`, `sqlmap`, `ffuf`, `curl`, `python3`. No wordlists are
installed (`/usr/share/wordlists` is missing) — provide your own small lists.

**Scenarios** (`uv run afw scenario list`) — each run is limited by a maximum duration:
| Scenario | Family | Max | Runs needed |
|---|---|---|---|
| `web-bruteforce-login` | credential brute force | 900 s | 3 test + 1 validation |
| `web-sqli-probe` | SQL injection | 900 s | 3 test + 1 validation |
| `net-portscan` | port scan | 600 s | 3 test + 1 validation |
| `net-ssh-guessing` | SSH guessing (WAF01:22, blocked by the firewall) | 900 s | 3 test + 1 validation |
| `web-content-discovery` | forced browsing — **the "unseen family"**, run it *after* the others | 900 s | 3 test + 1 validation |
| `low-and-slow-bruteforce` | slow brute force — **holdout, run last, evaluated once** | 3600 s | 3 |
| `net-slow-scan` | slow scan — **holdout, run last, evaluated once** | 3600 s | 2 |

Runs of the same family must be **separate sessions, hours apart**. Order: known families first, then
`web-content-discovery`, then the two holdouts.

**Target and limits (the harness enforces most of this):** attack **only from 10.77.10.10**, **only**
against `https://10.77.30.10/` (and WAF01 ports 22/80/3306 for the scan/SSH scenarios). **Never**
10.77.50.0/24 (management) or 10.77.60.0/24 (database), never anything else, never the public
Internet.

**Before every run**
```bash
cd ~/uot/ai-adaptive-firewall
uv run afw lab status          # all 8 VMs "started"
uv run afw lab verify          # must say 41/41 checks passed
curl -s --cacert ~/.config/afw/pki/lab-ca.pem https://10.77.50.10:8080/api/health   # status ok, mode monitor, telemetry_degraded false
uv run afw scenario watchdog & # stops ATK01 automatically if a run exceeds its maximum time
```
**Keep it modest:** FW01 has limited memory. Do **not** run more than about 50 simulated users at
once, and watch the IDS heartbeat on the dashboard afterwards (§10).

**One run**
1. On USR01 start **2 new benign background users** with unused addresses from **10.77.20.200–.249**
   (never reuse an address). Copy the exact command from `docs/TEAM_ATTACK_QUICKSTART.md` §4 step 1.
2. Open the run **before** starting the tool:
   `uv run afw scenario begin <scenario> <your-name> --notes "<tool, version, options, background users>"`
   → prints a **RUN_ID**. Write it down.
3. On ATK01 run your tool against the target. At each phase change:
   `uv run afw scenario mark <RUN_ID> "phase 2: …"`.
4. Stop the tool first, then `uv run afw scenario end <RUN_ID>`.
   **Emergency:** `uv run afw scenario abort <RUN_ID> "reason"` (powers ATK01 off).
5. Wait ~5 minutes (benign tail), then write the manifest and copy it to CTRL01:
   ```bash
   uv run afw scenario manifest <RUN_ID> /tmp/<RUN_ID>.json --benign 10.77.20.200,10.77.20.201
   scp -F ~/.config/afw/ssh_config /tmp/<RUN_ID>.json ctrl01:/tmp/
   ```
6. On CTRL01 (`ssh -F ~/.config/afw/ssh_config ctrl01`, then set the alias once):
   ```bash
   alias afwc='sudo -u afwctl env -C /var/lib/afw AFW_CONFIG=/etc/afw/lab.yaml AFW_DATA_DIR=/var/lib/afw AFW_API_TOKENS_FILE=/etc/afw/secrets/api_tokens.yaml /opt/afw/venv/bin/afw'
   afwc dataset capture <dataset-id> --manifest /tmp/<RUN_ID>.json --purpose test
   afwc dataset validate <dataset-id>     # any FAIL means: do not use this dataset
   ```
   Use `--purpose validation` for the single validation run per family and `--purpose holdout` for
   the two holdout scenarios. Dataset ids must be new: capture will not overwrite an existing one.
7. **Write down every run you begin, including aborted ones.** Do not hide failures.

**Rules for a series:** do not change thresholds, models or profiles between runs of a family; do not
re-run "until the numbers look better"; do not use replayed or synthetic attack files as evidence.

### 9.2 What happens after the runs (agent / whoever continues)
```bash
afwc experiment evaluate --datasets <ids> --streaming --warmup p7-sel,p7-sel-shift --out /tmp/eval.json
afwc experiment supervised --train <runs> --test <other runs>
afwc experiment supervised --train <runs> --withhold content_discovery --introduce <first run> --test <later runs>
```
This produces the five-way comparison (static / frozen ML / supervised / novelty / adaptive hybrid),
closes **gates B and E**, and gives the gate the attack data it needs. If a candidate then qualifies,
**one human-approved promotion** with probation closes **gate C**; running `docs/FINAL_DEMO.md` closes
**gate G**.

### 9.3 Work that does not need attack traffic (can start immediately)
Calibrate the scan limit on lab benign traffic (#6); gather more public captures for repeat runs and
more families (#3, #4); leave-one-family-out testing; features for slow/distributed attacks.

### 9.4 Decisions waiting on the owner
Copy the encrypted backups off this machine (#16) · whether to push the 96 local commits to GitHub ·
whether to simplify the FW01 root password · when to lock the VM passwords again (#18).

**Time left:** about **one afternoon of team work, then about one day of evaluation**. A calendar date
depends on when the team schedules the runs.

---

## 10. Running the lab day to day

| Task | Command |
|---|---|
| Is everything up? | `uv run afw lab status` |
| Start the lab (after a host reboot, if it did not restart itself) | `uv run afw lab start` (≈2–3 min until the controller answers) |
| Check isolation | `uv run afw lab verify` → 41/41 |
| Run all checks | `bash scripts/final_verification.sh` → 11/11 (takes ≈7 min) |
| Re-apply FW01 swap/boot hook | `uv run afw lab provision-fw` |
| Deploy code changes to CTRL01 | `uv run afw lab deploy --limit ctrl01` |
| Dashboard from your laptop | `ssh -N -L 18080:10.77.50.10:8080 gns3@<host>` then open `https://localhost:18080/`, click **API token**, paste the *dashboard* token |
| Run unit tests only | `uv run pytest -o addopts="" -q` (live-lab tests need `AFW_LAB=1`) |

**Known gotchas**
- **Host rebooted?** The lab usually restarts itself; if not, `uv run afw lab start`.
- **IDS heartbeat goes stale** (dashboard → Telemetry health, or `/api/overview` → `telemetry.sensors.ids`):
  on FW01 run `service cron start` (cron drives the heartbeat watchdog). If Suricata is missing on FW01
  after a heavy capture, it was likely killed for memory — tell the owner/agent; rebooting FW01 clears it.
- **Generators crash with SSL timeouts** when too many simulated users run at once — keep it under ~50.
- **`dataset capture` fails with "exists"** — the dataset id is taken; use a new id or delete the old one.
- **`pgrep` watchers match themselves** — poll log files instead.
- **`uv add` changes `pyproject.toml`** — use `uv run --with <pkg>` for one-off analysis libraries.

---

## 11. Access (logins)

<!--CREDENTIALS-->
**Passwords and tokens are not stored in this repository (by rule: secrets live only under
`~/.config/afw/` on the lab host, never in Git).** Ask the owner for the access sheet, or, if you
have a login on the lab host, read `~/.config/afw/LAB_ACCESS.md`. The kinds of login that exist:

| What | Where | Login |
|---|---|---|
| Linux VMs (CTRL01, WAF01, APP01, DB01, DESK01, USR01, ATK01) | GNS3 console, or SSH | user `afw` — password and key from the owner; passwordless `sudo` |
| FW01 (OPNsense firewall) | https://10.77.50.1 or serial console | user `root` — password from the owner |
| GNS3 server | http://127.0.0.1:3080 on the host | from the owner |
| Controller API / dashboard | https://10.77.50.10:8080 | bearer tokens (viewer / operator / admin) from the owner |
| Database | 10.77.60.10:5432 from DB01/APP01 | user `rental` — password from the owner |
| Web app test accounts | https://10.77.30.10/ | synthetic users `user1`…`user50` (password pattern `pw-N`) |

### 11.1 ONE command to open every website (Tailscale)

The lab lives on the host (Tailscale address **100.103.204.8**). Install Tailscale, join the
network, then paste **this one command** into a terminal on your own computer and leave it running:

```bash
ssh -tt \
    -L 18080:10.77.50.10:8080 \
    -L 18443:10.77.50.1:443 \
    -L 13080:127.0.0.1:3080 \
    -L 18444:127.0.0.1:18444 \
    gns3@100.103.204.8 \
    'ssh -F ~/.config/afw/ssh_config -N -L 127.0.0.1:18444:10.77.30.10:443 usr01'
```

It asks for the host login once, then everything below works. **Ctrl+C closes all of it.**

| Site | Open this in your browser | What it is | Login |
|---|---|---|---|
| **Dashboard / controller** | https://localhost:18080/ | Live detections, risk, models, learning lifecycle, mode | Paste a token (viewer is enough to look) |
| **FW01 OPNsense** | https://localhost:18443/ | The firewall: rules, aliases, Suricata alerts | user `root` + the FW01 password |
| **GNS3 web interface** | http://localhost:13080/ | The lab canvas, start/stop VMs, consoles | the GNS3 user and password |
| **Rental web app** (the protected site) | https://localhost:18444/ | The site as a customer sees it (reached through USR01) | `user1`…`user50`, password `pw-1`…`pw-50` |

Accept the browser's certificate warning (the lab has its own certificate authority).

**Warnings**
- **Do not browse the rental app during an attack run or a dataset capture.** Your clicks arrive from
  USR01 and are recorded as normal traffic, which contaminates the evidence. The other three sites are
  management traffic and are safe at any time.
- Do not use the `admin` token to browse the dashboard: it can switch the controller to enforce mode.
- If a port is already used on your computer, change the number before the first colon
  (`-L 28080:...`) and use that number in the browser.
- A shell on any VM: `ssh -J gns3@100.103.204.8 afw@<VM address>` (addresses in section 2); the account
  has passwordless `sudo`.
- Not web pages, so not above: the FW01/VM consoles (telnet ports in section 11) and the database
  (port 5432, only from DB01/APP01).

---

## 12. Rules of the road

1. **Monitor mode only** for attack runs and experiments. Enforce mode is off by design.
2. **Attack only from ATK01, only at WAF01.** Never management or database networks, never outside the lab.
3. **Never commit secrets.** Nothing under `~/.config/afw/`, no passwords, tokens or private keys in Git or chat.
4. **Do not weaken a test to get a pass.** If a result is bad, report it; negative results are valid.
5. **Test sets are single-use.** Do not tune on a final-evaluation set.
6. **Say what kind of evidence it is.** Offline public-capture results and live-lab results are different
   gates; never present one as the other.
7. **Back up before big changes** (`scripts/make_offhost_backup.sh`), and re-run `scripts/final_verification.sh` after.
8. **If you correct a claim, say so** (see the `ERRATUM_*` documents for how).

---

## 13. Glossary

| Term | Meaning |
|---|---|
| **Window** | A short slice of time (30 s web, 60/300 s network) for one source address, summarised as numbers |
| **Champion / challenger** | The model in charge / a copy learning in the background |
| **Shadow** | Runs and is recorded, but changes nothing |
| **Gate** | Automatic checks a challenger must pass before a human may promote it |
| **Probation / rollback** | A watched period after promotion; automatic return to the previous model if it misbehaves |
| **Recall** | Of the real attacks, the share detected |
| **False-positive rate (FPR)** | Of the normal traffic, the share wrongly flagged |
| **Family** | A kind of attack (brute force, SQL injection, scan, …) |
| **Held-out / anchor** | Data the model never learned from, fixed in advance, used only to test |
| **Rehearsal** | Replaying old examples while learning new ones, so old knowledge is not lost |
| **Burst** | One continuous stretch of attack activity; the real "number of independent examples" |
| **Offline** | Analysing recorded traffic; nothing is sent on any network |
| **Suricata / ET Open** | The intrusion detector on FW01 / its standard free rule set |
| **CIC-IDS2017** | A public dataset of recorded attacks (Canadian Institute for Cybersecurity) |
| **pf** | The FreeBSD packet filter inside OPNsense |
| **mTLS / RELP** | Mutually authenticated TLS / a reliable logging protocol |
| **Protected address** | An address the system may never block (management, DB, firewall, WAF/APP networks) |
| **Gate A–G** | The seven acceptance gates (infrastructure, detection, adaptation, enforcement, independent value, security/ops, academic defensibility) |

---

## 14. Appendix: the names you will meet, the data, the generator, rebuilding, and what to read

### 14.1 Decoder for the milestone and experiment names

You will see these codes in file names, commit messages and older documents. They are the project's
history; you do not need them to run the attack series, but you need them to read the evidence.

| Code | Plain meaning | Result in one line | Detail |
|---|---|---|---|
| **M0–M9** (27 Oct) | Ten engineering milestones: audit, evidence correlation, online learning, champion/challenger lifecycle, adaptation experiments, telemetry v2, attack-evaluation harness, GeoIP, dashboard panels, documentation | All built; each found and fixed real defects (a data-poisoning flaw in M4, telemetry stalls in M5) | `PROJECT_REPORT_2026-10-28.md` §3.1 |
| **P1–P5** (28 Oct) | Five priorities set by the owner: benign generalisation, sensitivity invariance, independent attack evaluation, real online adaptation, hardening | P1 negative (model flagged 13 of 16 new normal users); P3 blocked on attack runs; P5 hardening done | same, §3.2 |
| **P6 / P7 / A2** | Choose among seven candidate models that stop flagging new normal users without becoming blind. P7 is the same test on clean data after A2 fixed a generator/app mismatch (`/reviews` returned 404) | No candidate eligible: one forgetful user kept tripping the brute-force rule | `P6_GENERALIZATION_AND_SENSITIVITY.md`, `RESULTS.md` §3b–3c |
| **A3 → A4** | Make login protection per-account and graduated (throttle, then deny, only on the login page). A3's final test failed (shared-household users); A4 fixed it by making "many accounts from one address" a ceiling only | A4 passed on fresh data: 0 of 2,791 legitimate logins refused | `A3_AUTH_CONTROLS.md`, `A4_AUTH_HOUSEHOLD_REVALIDATION.md` |
| **NV1 → NV2** | Same idea for ordinary non-web network use (DNS, NTP, ping, HTTPS). NV1 exposed a sweep rule firing on normal behaviour; NV2 revalidated on new users | See `RESULTS.md` §3e–3f | `NV1_…`, `NV2_…` |
| **N1/N2** | The network-novelty detector (port/host scan behaviour) | Fixed ceiling misses slow scans | `PROJECT_SUMMARY_AND_READINESS.md` §4.3 |
| **ADR-001…044** | 44 architecture decision records: what we chose, why, what we rejected, how it was verified | Read an ADR before changing the thing it covers | `docs/ARCHITECTURE_DECISIONS.md` |
| **Phase E / "final"** | A test set used exactly once, after the protocol was committed. It cannot be reused | Never tune on a `*-final` dataset | each protocol document |
| **Predeclared** | The pass/fail criteria were written and committed before the data was looked at | This is how we avoid fooling ourselves | any `engineering/*` protocol |
| **SYNTHETIC** | Feature-level test cases (e.g. "add 12 failed logins to a normal window"). They contain no traffic and are **never** described as attack detection | Regression checks only | `TEAM_ATTACK_QUICKSTART.md` §0 |

### 14.2 The recorded datasets (on CTRL01, `/var/lib/afw/datasets/`, 40 of them)

A dataset is a folder with three files: `manifest.json` (id, purpose, seed, start/end, which source
address played which role, counts, and sha256 of the data), `observations.jsonl.gz` (web/WAF/app
events) and `net_events.jsonl.gz` (network events). The manifest is the ground truth: if a source is
listed as `benign` or as an attacker with an attack type and time range, that is the label. A dataset
is only usable for evaluation if its manifest is complete.

| Prefix | What it is |
|---|---|
| `real-benign-*`, `real-drift-*` | First real lab recordings: baseline users and the "drift" used in the online-learning experiments (27 Oct) |
| `demo-*` | Small sets for the demonstration |
| `p1-*`, `p6-*`, `p7-*` | Benign users for P1/P6/P7: `-train`, `-val` (calibration), `-sel` (selection, once), `-final` (final, once), `-shift` (an unusual population) |
| `a3-*`, `a4-*` | Login-protection sets; `-hh` = multi-account households, `-shift` = shared addresses |
| `n2-*`, `nv1-*`, `nv2-*` | Ordinary network-use users (DNS/NTP/ping) |

**All of these are benign.** There is no recorded attack dataset from the lab yet; that is exactly
what your attack runs will create (§9). The public CIC-IDS2017 evidence is separate and lives under
`artifacts/evidence/offline-cic-*` (large PCAPs are not in Git; each folder has a `provenance.txt`
with the file's sha256 and source).

Capture a dataset from CTRL01 with `afw dataset capture <id> --manifest <manifest.json> --purpose
train|validation|test`. Never reuse an ID, a source address range or a seed that a training set used
(this once leaked and had to be recaptured; the check is `benign_users_unseen`).

### 14.3 The benign traffic generator (`traffic/benign_personas.py`)

Stdlib-only Python that runs **on a client VM** (USR01) and plays ordinary customers of the rental
app: browse cars, read reviews, log in, book, occasionally mistype a password and correct it. It is
**not** an attack tool: only valid routes and valid credentials.

| Setting (environment variable) | Meaning |
|---|---|
| `AFW_SOURCES` | Source addresses to use, one simulated user per address (earlier experiments used addresses up to about `.199`; `.200–.249` are reserved for the team) |
| `AFW_MODE` | `shared` (one loop) or `personas` (one concurrent user per source, each with its own habits) |
| `AFW_PERSONA_SET` | `v1` (original) or `v2` (eight archetypes: casual, regular, forgetful, power, household, stale-link, slow reader, city searcher) |
| `AFW_NET` / `AFW_NET_HABITS` | `1` adds DNS/NTP/ping/HTTPS activity; habit light/normal/heavy |
| `AFW_SEED`, `AFW_DURATION` | Reproducibility seed; seconds to run |
| `AFW_TARGET_IP`, `AFW_TARGET_NAME`, `AFW_LAB_CA`, `AFW_GATEWAY` | Where it points and which CA it trusts |

You run it before each attack run so there is realistic normal traffic around the attack. The exact
command is in `TEAM_ATTACK_QUICKSTART.md` §1.

### 14.4 Rebuilding the lab from nothing

You do **not** need this to run the attack series (the lab exists and starts on its own). You need it
if the host is replaced or a VM is destroyed. Full text: `docs/DEPLOYMENT.md`.

1. **Host:** Ubuntu 24.04, GNS3 2.2.61, QEMU/KVM, about 16 GB RAM, `uv`. Run `lab/host/bootstrap-host.sh`
   (read it first; it needs sudo and creates the management interface `afw-mgmt0` 10.77.50.254 and the
   route to `10.77.0.0/16`). Put GNS3 API credentials in `~/.config/afw/gns3.env`.
2. `uv sync` in the repository.
3. Bake the base images: `lab/images/bake-golden.sh` (and `bake-desktop.sh` for DESK01).
4. `uv run afw lab build` (creates the GNS3 nodes and links from `lab/gns3/topology.yaml`; FW01 gets
   2560 MB RAM, not 1536, or Suricata runs out of memory), then `uv run afw lab start`.
5. `uv run afw lab provision-fw` (OPNsense zones, rules, API user, certificate, swap file and the boot
   hook) then `provision-ids` (Suricata) then `deploy` (Ansible: app, WAF, controller, sensors, mTLS
   certificates) then `layout`.
6. `uv run afw lab verify` must say **41/41**. Then `scripts/final_verification.sh` runs everything
   (tests, isolation, live tests).
7. Secrets (PKI, tokens, passwords) are regenerated into `~/.config/afw/` by `deploy`; they never
   enter Git. Back them up with `scripts/make_offhost_backup.sh` (encrypted).

Treat steps 3–5 as "ask the owner first": they recreate machines. Use `afw` through `uv run` on the
host; on CTRL01 the installed binary is `/opt/afw/venv/bin/afw` (see §9 for the alias).

### 14.5 Reading order, if you want the depth

1. This document (you have done it).
2. `docs/TEAM_ATTACK_QUICKSTART.md`, the short exact attack-run procedure; `docs/engineering/P3_TEAM_ATTACK_RUNBOOK.md` for the reasons.
3. `docs/ARCHITECTURE.md` and `docs/ARCHITECTURE_DECISIONS.md` (the 44 decisions).
4. `docs/RESULTS.md` (every measured number, with its limits) and `docs/STATUS_LIMITATIONS_FIXES.md`.
5. The three corrections, so you do not repeat our mistakes: `engineering/ERRATUM_FORGETTING.md`,
   `engineering/ERRATUM_STATIC_BASELINE.md`, `engineering/OFFLINE_THIRD_CAPTURE.md`.
6. `docs/OPERATOR_GUIDE.md`, `docs/SECURITY_AND_LIMITATIONS.md`, `docs/THREAT_MODEL.md`.
7. `docs/engineering/GATE_STATES.md`, the authoritative state of the seven gates.

### 14.6 What this handoff still does not cover

- **ML internals line by line** (feature definitions, forest parameters): read `src/afw/ml/` and
  `docs/ADAPTATION_DESIGN.md`.
- **The OPNsense and Ansible internals**: read `lab/ansible/` and `src/afw/lab/provision_fw.py`.
- **The host's own login password** is not stored anywhere; ask the owner.
- **Credentials** are in the private copy of this document, not in Git.
