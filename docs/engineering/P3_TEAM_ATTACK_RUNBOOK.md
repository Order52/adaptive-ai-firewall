# P3: team attack-evaluation runbook

Attack traffic for Gates B and E must come from the **team**, with established tools,
from ATK01, against the lab's own WAF01 only. The project does not generate attack
traffic. This runbook is the exact sequence; the harness behind it is described in
`M6_ATTACK_EVALUATION.md` (ADR-032).

Run `afw` commands on CTRL01 as the controller user, for example:

```bash
ssh ctrl01
alias afwc='sudo -u afwctl env AFW_CONFIG=/etc/afw/lab.yaml AFW_DATA_DIR=/var/lib/afw \
  AFW_API_TOKENS_FILE=/etc/afw/secrets/api_tokens.yaml /opt/afw/venv/bin/afw'
```

## 0. What is needed for the gates

| Need | Runs | Purpose |
|---|---|---|
| `web-bruteforce-login`, `web-sqli-probe`, `web-content-discovery`, `net-portscan` | ≥ 3 each, on different days or at least hours apart | Gate B detection metrics with run-level CIs; Gate E comparison |
| `low-and-slow-bruteforce` | ≥ 3 | **holdout**: run last, evaluate once, never tune on it |
| one run of each family as `--purpose validation` | 1 each | attack recall for the M3 promotion gate (`challenger evaluate --attack`) |

Runs of the same family are independent only if they are separate sessions. Do not
split one long session into several "runs".

## 1. Before every run (operator checklist)

On the host:

```bash
uv run afw lab status            # all 8 VMs started
uv run afw lab verify            # expect every check passed (41/41 on 2026-10-28)
curl -s https://10.77.50.10:8080/api/health    # "status":"ok", "telemetry_degraded":false
```

* Operating mode **monitor** for detection runs (the dashboard header shows it; change
  with `POST /api/mode` or the MCP `set_mode` tool, admin only). In monitor mode the
  full attack is recorded, and the replay measures what each arm *would* have done.
  Enforcement is measured separately (§5).
* Pick **benign background addresses** for this run that no earlier run used. Free ones
  are listed in `artifacts/evidence/p1-2026-10-28/`. Taken: 10.77.20.10–82 (P1 and
  earlier), .90–.97 (generator smoke tests), .100–.197 (P6). Use .200–.249 for team
  runs, two new addresses per run, and note them in the run's `--notes`.
  Each run gets its own users, so FPR is measured on independent people.
* In a second CTRL01 terminal: `afwc scenario watchdog` (stops ATK01 if the run exceeds
  its registered maximum duration).

## 2. One run, step by step

```bash
# once per USR01 boot (/tmp is cleared on reboot), from the repository on the host:
#   scp -F ~/.config/afw/ssh_config traffic/benign_personas.py usr01:/tmp/
# t = -5 min: benign background on USR01, one process per user (2 users per run)
ssh usr01 'for ip in 10.77.20.200 10.77.20.201; do
  sudo ip addr add $ip/24 dev ens3 2>/dev/null
  AFW_MODE=personas AFW_SOURCES=$ip AFW_DURATION=1800 AFW_SEED=${ip##*.} \
    setsid nohup python3 /tmp/benign_personas.py >/tmp/bg_$ip.log 2>&1 </dev/null &
done'

# t = 0: record ground truth, THEN start the tool
afwc scenario begin web-sqli-probe <your-name> --notes "sqlmap 1.8, default level"
#   -> prints RUN_ID, the max duration and the allowed targets
# on ATK01: start the tool against https://10.77.30.10/ only

afwc scenario mark <RUN_ID> "phase 2: authenticated endpoints"   # at each phase change

# when finished: stop the tool on ATK01 FIRST, then
afwc scenario end <RUN_ID>
# if anything is wrong at any time (wrong target, runaway tool):
afwc scenario abort <RUN_ID> "<reason>"     # powers ATK01 off, recorded in the journal

# t = end + 5 min: benign tail done (AFW_DURATION covers it)
```

Rules:

* Targets other than those `scenario begin` prints are refused by the registry; FW01
  allows only ATTACK → 10.77.30.10:443 in any case.
* Write in `--notes` the tool, version and main options, so the run is reproducible.
* Do not change detector settings, thresholds or the profile between runs of a series.

## 3. Capture the run

```bash
afwc scenario manifest <RUN_ID> /tmp/<RUN_ID>.json --benign 10.77.20.200,10.77.20.201
afwc dataset capture atk-<family>-<yyyymmdd>-<n> --manifest /tmp/<RUN_ID>.json --purpose test
#   (--purpose validation for the one validation run per family; holdout for low-and-slow)
afwc dataset validate atk-<family>-<yyyymmdd>-<n>   # exit 1 on any FAIL
```

`dataset validate` checks integrity (sha256), counts and time range, unique request
ids, that every observed source is labelled and no address is both benign and attack,
that attackers are in the ATTACK zone and have an `attack_type`, that attack data is
not marked `train`, that the data is not synthetic, and that the run overlaps no
dataset of another split. It warns on: labelled sources with no HTTP observation (an
attack stopped at FW01 leaves none: say so), attacker traffic outside its labelled
window, observations without full provenance, aborted runs, a subset of the same
split, and benign addresses that also appear in training/validation datasets. **A
dataset with a FAIL is not used**; re-capture or relabel it and validate again. Paste
the WARN lines into the run's entry in the results.

The manifest's time range and labels come from the journal, not from memory. The
attacker address is labelled malicious, the background users benign.

**What to expect for brute force (ADR-039).** If the attacker *only* fails logins,
the behaviour anomaly is the same requests as the AUTH evidence, so there is one
corroborating category: the expected decision is a STRICT rate limit with
`insufficient_corroboration_for_block`, not a block. A block needs a second
independent signal (WAF, IDS, or behaviour that stays anomalous without the failed
logins). This is a prediction to test, not a result: record what actually happens.

## 4. Evaluate (after all runs of a family)

```bash
# Gate B / E: M0 static, M1 statistical, M2 ML on the trusted profile
afwc experiment evaluate --datasets atk-sqli-20261101-1,atk-sqli-20261102-2,... \
  --out /tmp/eval-trusted.json
# the same runs on the reviewed candidate profile (not promoted)
afwc experiment evaluate --version 3 --datasets ... --out /tmp/eval-v3.json
# the online challenger's promotion gate, with real attack recall
afwc challenger evaluate --benign p1-test --attack atk-sqli-20261101-v
```

Each report gives, per arm: attack recall, precision, benign FPR, attack sources
contained, median first-attack-to-action latency, attack requests exposed, and
legitimate request success, with confidence intervals over **runs**. Copy the JSON into
`artifacts/evidence/<date>/` and the numbers into `RESULTS.md` with the dataset ids.

The holdout family is evaluated **once**, after everything else is frozen.

## 5. Enforcement runs (Gate D under attack)

After the detection series, one run per family in **enforce** mode shows real
containment: proposals become OPNsense or WAF policies, are read back and verified, and
expire. Record them the same way (`scenario begin/end`, capture with
`--purpose test`), but report them separately, because enforcement changes the traffic
that follows.

## 6. What not to do

* No targets outside the registry, no attacks from USR01, no scans of MGMT or DB.
* No synthetic or replayed attack files as evidence (`experiment evaluate` refuses
  them).
* No re-running a run until the numbers look better: every run that was begun is
  reported, including aborted ones.
