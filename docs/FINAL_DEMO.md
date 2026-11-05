# Final demonstration (15–20 minutes)

A repeatable walkthrough on the live GNS3 lab. Every step gives the command, what the
audience should see, and what it does **not** show. Commands were re-run against the live lab on
2026-11-05 (isolation 41/41, live tests 14/14, dashboard rendered with no console errors). Steps marked **[NEEDS TEAM ATTACK RUNS]** only work once the team has
recorded attack runs (`TEAM_ATTACK_QUICKSTART.md`).

The rule for the whole demo: show what is measured, and say what is not.

## 0. Before the audience arrives (5 min)

```bash
cd ~/uot/ai-adaptive-firewall
uv run afw lab status          # 8 VMs (APP01 ATK01 CTRL01 DB01 DESK01 FW01 USR01 WAF01) "started"
uv run afw lab verify          # 41/41 checks passed
curl -s --cacert ~/.config/afw/pki/lab-ca.pem https://10.77.50.10:8080/api/health | python3 -m json.tool | head -12
#   expect "status": "ok", "mode": "monitor", "telemetry_degraded": false, "model_error": null
```

Dashboard, from the presenting laptop: use the one command in `TEAM_HANDOFF.md` §11.1
(`ssh -tt -L 18080:… gns3@100.103.204.8 …`), then open `https://localhost:18080/`, click
**API token**, paste a **viewer** token and press Connect. The new **Firewall & enforcement
(live)** panel under the key figures shows FW01 and WAF reachability, blocked sources, WAF
denies and rate limits, country blocks, the mode and the latest decisions; the bar under the
header jumps to each section.

**Five minutes before:** start benign background traffic (step 2) so the charts are not flat.
The lab is idle otherwise: no sources, no requests, risk 0.

Keep the mode **monitor** for the whole demo except step 6. The trusted profile v2 has
too many false positives for enforce mode on new users (step 2, `RESULTS.md` §3a–3b).

## Dashboard tour (3 min, do this first)

The status banner at the top is the answer to "is anything wrong?": **All clear**, **Watch**,
**Possible malicious activity** or **System needs attention**, with the reasons beside it.
Six tabs:

* **Overview**: banner, key figures, live firewall and WAF state read back from the devices,
  latest enforcement decisions, risk and request charts.
* **Threats**: anomalous detections, live sources with risk, IDS-only sources, login controls.
  Lab probe addresses are tagged "lab infrastructure" and are never counted as a threat.
* **Network**: connections, DNS, TLS, firewall drops, network-novelty detector.
* **Firewall & controls**: restrict a source (firewall block, WAF deny, rate limit strict or
  moderate; validator check, then a confirmation), approve / reject / revoke decisions, change
  mode (admin token only), and the configuration in force (thresholds, safety limits, protected
  networks, protected application).
* **Learning**: models, profiles, shadow challenger, promotion gate. Promotion is not in the
  dashboard on purpose.
* **System**: sensor health and the audit trail.

Use a **viewer** token to present (read-only). Use an **operator** token only for the live
control demo in step 6. The token decides what the page lets you do; the server enforces it.

**What "monitor" means:** it holds back the AI's own decisions (recorded, not applied). Actions
you request yourself, from the dashboard or MCP, are applied and verified even in monitor mode,
and expire on their own.

## 1. The lab and its isolation (2 min)

* `uv run afw lab status` and the dashboard's topology/resources: 8 VMs, 6 zone
  switches, FW01 between every zone.
* `uv run afw lab verify` → 41/41: clients cannot bypass the WAF, the database is
  reachable only from the app tier, management reaches everything.
* MCP (Claude Code): *"show me the entire lab and the status of every device"* →
  `lab_topology`, `lab_health`.

## 2. Legitimate users, and the main limitation (3 min)

On USR01 (one new, never-used address):

```bash
ssh -F ~/.config/afw/ssh_config usr01
sudo ip addr add 10.77.20.198/24 dev ens3 2>/dev/null
AFW_MODE=personas AFW_PERSONA_SET=v2 AFW_SOURCES=10.77.20.198 AFW_DURATION=180 AFW_SEED=4242 \
  python3 /tmp/benign_personas_a2.py      # copy traffic/benign_personas.py there first if missing
```

* Dashboard "Live sources": the source appears; requests reach the app (WAF → APP01).
* **Say it plainly:** the trusted v2 model was trained on one 5.4-minute run from six
  addresses. On new legitimate users it proposes restrictions for most of them
  (13 of 16 in P1; 12 of 16 in P6). In monitor mode these are proposals only, shown as
  "not applied". This is the project's main measured weakness and the reason for P6/P7.

## 3. Models, profiles and versions (2 min)

* Dashboard "Models & profiles": v1 retired (synthetic), **v2 trusted**, v3 and v4
  candidates (evaluated, **not promoted**: they fail the predeclared sensitivity
  criterion, P1).
* MCP: *"show the machine-learning model's current performance"* → `model_status`.
* Every model carries its training/validation dataset ids, artifact sha256 and
  threshold; a corrupt artifact is refused at load and before any switch (ADR-040).

## 4. An explainable decision (2 min)

* On a policy row (step 2's proposals) click **Explain**: evidence categories and points,
  detector scores against thresholds, top feature drivers, model and profile versions,
  the decision and why it is not a block (corroboration rule), effect on traffic.
* MCP: *"why did the AI act on 10.77.20.198?"* → `policy_history` → `explain_policy`.
* Point out the evidence-independence rule (ADR-039): behaviour that is anomalous only
  because of failed logins does not count as a second category.

## 5. Safety guards (1 min)

* MCP: *"block 10.77.50.10"* (CTRL01, a management address) → **rejected** by the
  validator, never enforced.
* MCP: *"restart CTRL01"* → refused (control-plane guard).
* No MCP tool can promote a model; promotion needs the admin API and a passing gate.

## 6. Verified enforcement (2 min)

The reproducible version is the live-lab test suite (real OPNsense alias, WAF deny,
rate limit, read-back, probe verification, expiry, revoke, protected-address refusal):

```bash
AFW_LAB=1 uv run pytest tests/lab -o addopts="" -q     # 14 passed (2026-10-28 16:0xZ)
```

MCP tools for acting on the firewall (all validated, expiring, verified by read-back, and
recorded with origin `mcp`): `simulate_restriction`, `restrict_source` (action
`firewall_block`, `waf_deny`, `rate_limit_strict` or `rate_limit_moderate`), `block_source`,
`unblock`, `approve_policy`, `reject_policy`, `country_policy`, `set_mode` (admin token),
`feedback`. Checked live on 2026-11-05 on the demo address: each action applied, read back,
and was revoked with the removal confirmed by read-back.

Interactive version (optional): MCP *"block 10.77.20.198 for 2 minutes"* → the policy
goes `pending → enforced` only after FW01's alias is read back and a probe from that
address fails; *"unblock 10.77.20.198"* → removed and verified. Do this only on a demo
address, never on a P6/P7 or team address.

## 6b. Real country blocking, watched on a real desktop (2 min, added 2026-11-05)

USR01 carries a live XFCE/Firefox desktop (not simulated -- `TEAM_HANDOFF.md` §15 has the full
script and the two real-GeoIP limitations found while proving this). Open it with a VNC client
at `127.0.0.1:15901` (§11.1's tunnel now forwards it).

* Open Firefox, load `https://1.1.1.1/` -- works.
* MCP *"block AU outbound for real"* (`country_policy`, `country_code=AU`,
  `direction=outbound`, `simulated=false`) -- the dashboard's GeoIP card, or
  `active_policies`, shows it reach `enforced` after FW01's ~30 s pull and its own
  outbound egress probe.
* Reload `1.1.1.1` in Firefox -- "Firefox can't connect to the server". `8.8.8.8` (the
  control address) still loads.
* Revoke it -- after the next pull, `1.1.1.1` loads again.
* Say once: the **US itself is too large** for this mechanism (155,176 networks vs the
  40,000-per-direction cap, ADR-036) -- the validator refuses it cleanly rather than doing
  something unreliable. That refusal is worth showing too.

## 7. The adaptive lifecycle, honestly (3 min)

* Dashboard "Controlled adaptation": real **drift reports** (new endpoints, feature
  shifts) on legitimate traffic, with source counts.
* Dashboard "Online learning": the shadow challenger, windows learned, and the reasons
  windows were refused (tainted by the champion's own proposals, sensitive range,
  overlap). Fail-closed: the challenger cannot learn from sources the champion acted on.
* Dashboard "Promotion gate & probation": the last evaluation **failed**
  (`attack_recall_regression`: no real attack runs; `sensitive_invariance`). The gate
  is doing its job; nothing is promoted to satisfy a demo.
* Rollback: shown by evidence, not live (a live switch needs human authorization):
  `artifacts/evidence/p6-2026-10-28/reliability/switch-validation.txt` (process killed
  after each of the 8 writes of a rollback → previous profile always complete).

## 8. The research result (3 min)

* `RESULTS.md` §3a (P1): more varied training data removes the false positives but loses
  measurable sensitivity; neither model is promoted.
* `RESULTS.md` §3b (P6): seven designs, protocol committed before the data; **none
  qualified** at selection. The diagnosis found a behaviour-only rate-limit path and a
  generator defect (22–29 % of legitimate requests were 404/422 errors).
* `RESULTS.md` §3c (P7, amendment A2): the result after fixing those causes on new data.
* Explain the difference between the synthetic regression cases (feature-level, no
  traffic, measure sensitivity regression) and attack evaluation (step 10).

### 8b. Offline results on public attack captures (add 3 min)

Separate gate from the live lab; say so first. Details: `OFFLINE_THIRD_CAPTURE.md`,
`ERRATUM_FORGETTING.md`, `ERRATUM_STATIC_BASELINE.md`.

* Three independent CIC-IDS2017 days, replayed offline through our own pipeline.
* With a correctly configured Suricata (our first baseline was misconfigured and is
  corrected): static rules recall 0.434 / 0.133 / 0.282 vs ML 0.895 / 0.267 / 0.877. The two
  complement each other (union 0.908 on Thursday morning).
* Models are **family-specific** (cross-family recall about 0.1), and the real sample size is
  3–7 independent bursts per family: say it before anyone asks.
* Learning a new family works (0.45 to 0.9 depending on family) but **forgets the old one
  without rehearsal** (old-family recall down to 0.08); rehearsal fixes it (0.999). Batch
  retraining is the stable, cheaper alternative. No claim that online learning is better.

## 9. Telemetry liveness and recovery (2 min)

* On APP01: `sudo systemctl stop afw-heartbeat.timer`. After about 150 s the dashboard
  shows sensor **app stale** and telemetry degraded (automatic enforcement pauses).
  `sudo systemctl start afw-heartbeat.timer` clears it within seconds.
* `ssh -F ~/.config/afw/ssh_config ctrl01 sudo systemctl restart afw-controller` →
  the controller reloads profile v2 and its models and reconciles enforcement state;
  FW01's watchdog flushes dynamic blocks if the controller stays dead (~120 s).

## 10. Attack scenarios **[NEEDS TEAM ATTACK RUNS]** (2 min)

* The team runs one scenario live from ATK01 (`TEAM_ATTACK_QUICKSTART.md` §4), e.g.
  `web-bruteforce-login`, in monitor mode: the dashboard shows the attacker's evidence
  categories and the proposed response (pure brute force: strict rate limit, not a
  block, ADR-039).
* The measured comparison (static, frozen ML, streaming ML, hybrid; recall, FPR,
  latency, containment, with CIs over runs) comes from `afw experiment evaluate` on
  the recorded runs. Until those runs exist, say: **attack detection has not been
  measured**.

## Demo-day checklist

- [ ] `afw lab status`: 8 VMs started; `afw lab verify`: 41/41
- [ ] Health: mode monitor, `telemetry_degraded` false, all three sensors fresh
- [ ] Tailscale up; the one-command tunnel opens dashboard, OPNsense, GNS3 and the app
- [ ] Benign traffic running 5 minutes before (use an address the team does not use)
- [ ] Nothing else running: no capture, no attack run, no model promotion pending
- [ ] Say once, at the start: live attack detection is not yet measured
- [ ] Never enable enforce mode; verified-block demo only on a demo address (step 6)

## Questions to be ready for

| Question | Honest answer | Where |
|---|---|---|
| Does it detect attacks? | On recorded public captures yes (family-specific, modest sample); in our own lab not measured yet: needs labelled team runs | `OFFLINE_THIRD_CAPTURE.md` |
| Why not enforce mode? | v2 restricts most new legitimate users | §3a–3b |
| Is the AI better than static rules? | Unknown until the four-way comparison on attack runs | runbook §4.1 |
| Does it adapt? | Learns and detects drift live; no challenger has passed the gate; nothing promoted | §6b, step 7 |
| What if a model file is corrupt? | Refused before a switch; at start-up the controller runs without ML and reports degraded | ADR-040 |
| Can an attacker poison learning? | Bounded by taint, tenure, rate and share caps; ≥ 4 colluding sources remain a risk | M4 |

## One-command rebuild

`afw lab build → start → provision-fw → provision-ids → deploy → layout → verify`
(`DEPLOYMENT.md`), then capture benign traffic and `afw train bootstrap`.
