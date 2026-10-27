# Final demonstration (10–15 minutes)

A repeatable walkthrough of the AI-Adaptive-Firewall loop on the live GNS3 lab.
Each step says what to show, the command/UI, and what the audience should see.
Items marked **[BENIGN — runs today]** work now; **[NEEDS ATTACK TRACE]** are ready
in code and run once team-supplied attack traces exist (see `docs/EXPERIMENTS.md`).

Open the dashboard first: `ssh -N -L 18080:10.77.50.10:8080 gns3@<host>` →
`http://localhost:18080/` (paste the dashboard token).

## 1. Lab health & topology (1–2 min)
- `afw lab status` → 6 guests + infra, all started.
- `afw lab verify` → **37/37** zone-isolation checks (no WAF/app bypass, clients
  isolated, management reaches all).
- Dashboard tiles: mode, trusted profile **v2**, ML model, live sources, RSS.
- Via Claude Code (MCP): *"show me the entire lab and the status of every device"*
  → `lab_topology`.

## 2. Normal application behaviour **[BENIGN — runs today]** (2 min)
- Generate legitimate traffic from clients:
  `AFW_SOURCES=10.77.20.10 AFW_DURATION=90 python3 traffic/benign_personas.py` (on USR01).
- Dashboard "Live sources": each source **risk 0 / band none**; detector scores sit
  **below** threshold. "Requests observed" chart shows the real traffic.
- Point out: the profile was **trained on real lab traffic**, not synthetic fixtures.

## 3. The model & profile (1–2 min)
- Dashboard "Models & profiles": v1 (synthetic) **retired**, **v2 trusted** (361
  windows, 6 sources), three detectors with real validation FPR (~1.3%).
- MCP: *"show the machine-learning model's current performance"* → `model_status`.
- "Baseline vs current": select a source → its features against the trusted q05–q99
  band (genuine, per-feature).

## 4. Why a correct profile matters (1 min)
- Dashboard "Adaptive policy decisions" shows earlier `rate_limit`/`watch` entries
  recorded **while the synthetic profile was active** ("monitor mode, not applied") —
  false positives on real users. After training the real profile, step 2's traffic
  scores 0. This is the value of application-aware learning, concretely.

## 5. Legitimate drift & controlled learning **[BENIGN]** (2 min)
- Dashboard "Controlled adaptation": real **drift reports** (e.g. `new_endpoint,
  feature_shift · population`) when legitimate traffic used routes the profile lacked;
  "Candidate evaluations" show the anti-poisoning gate (no single source may dominate).
- Narrate the lifecycle: shadow learning on reputation-gated traffic → candidate
  profile → human-reviewed promotion → rollback available. Attacker traffic cannot
  silently become "normal".

## 5b. Online learning, honestly (2 min)
- Dashboard **Online learning**: the challenger and the reasons windows were *not*
  learned. Explain fail-closed: sources the champion acted on are tainted.
- Dashboard **Promotion gate & probation**: no promotion without a passing gate and an
  admin. Show `RESULTS.md` §6b: on recorded real drift, HST false alarms fell from about
  65 % to about 3 %. The gate still refuses: no real attack runs, and sensitivity to
  auth abuse dropped. This is the gate doing its job.
- Show `RESULTS.md` §3: the frozen models raised many false positives on new benign
  users. This is the main limitation and the motivation for adaptation.

## 6. Explainable decision (1–2 min)
- On any policy row click **Explain** → the 8-section panel: what happened, why it was
  suspicious (evidence + points), model & profile versions, **occlusion feature
  attributions**, response chosen, enforcement result, effect on legitimate traffic.
- MCP: *"why did the AI act on <source>?"* → `policy_history` → `explain_policy`.
- Explanations are self-contained (snapshotted) and survive detection retention.

## 7. Safety guards **[runs today]** (1 min)
- MCP: *"block 10.77.50.10"* (a management address) → submitted then **rejected** by
  the validator; never enforced. *"restart CTRL01"* → **refused** (control-plane guard).
- These demonstrate the least-privilege broker and the typed-command-only design.

## 8. Research comparison (1–2 min)
- Dashboard "Static vs statistical vs ML-assisted experiments" / MCP
  `experiment_results`: **M0/M1/M2 on real held-out benign** → FPR 0, legit 100%,
  M1 ~63 µs vs M2 ~11.9 ms scoring. Rows are tagged by scenario so a synthetic demo is
  never mistaken for a lab result.

## 8b. Telemetry liveness (1 min)
- On APP01: `sudo systemctl stop afw-heartbeat.timer`. After about 150 s the dashboard
  shows sensor **app STALE** and "telemetry degraded". `sudo systemctl start
  afw-heartbeat.timer` clears it within seconds (measured 2 s).

## 9. Recovery (1 min)
- `ssh ctrl01 sudo systemctl restart afw-controller` → within seconds the controller
  reloads profile v2 + models and restores enforcement state. FW01's watchdog is the
  dead-controller fail-safe.

## 10. Attack scenarios (state honestly) (1 min)
- **[NEEDS ATTACK TRACE]** Scenario A (auth abuse), B (SQLi/CRS signature vs AI
  correlation), E (held-out novelty): the full pipeline — detection → correlation →
  proportional block → read-back + traffic verification → legitimate client preserved
  → expiry/rollback — is implemented and unit/integration-tested. It will run on real
  attack telemetry from team-run scenarios recorded with the M6 harness
  (`afw scenario …`, see `OPERATOR_GUIDE.md`). We do **not**
  claim attack results we have not measured.

## One-command rebuild
`afw lab build → start → provision-fw → provision-ids → deploy → layout → verify`,
then capture benign traffic and `afw train bootstrap`. See `docs/DEPLOYMENT.md`.
