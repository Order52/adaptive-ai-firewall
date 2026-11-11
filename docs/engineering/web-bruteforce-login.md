# Team attack run — `web-bruteforce-login` — session report, 2026-11-07

**Operator:** Order52 (manual attack, via hydra on ATK01) with Claude Code assisting on
harness orchestration (scenario begin/end/abort, manifests, dataset capture/validate,
watchdog, benign background traffic).
**Scenario:** `web-bruteforce-login` (`credential_bruteforce`), target `https://10.77.30.10/login` (WAF01), app `rental`.
**Outcome:** family fully evidenced — 3 test runs + 1 validation run, all captured and
validated with zero FAILs. Two real bugs were found along the way; both are described
below so the team understands exactly what happened and why.

---

## TL;DR

- `web-bruteforce-login` is **done**: 4 validated datasets, clean detections (`critical`
  band, 93+ risk score, correct attribution, zero false positives on 7 pairs of benign
  background addresses).
- **Bug 1 (hardware):** ATK01 (768 MB RAM, 1 vCPU, **no swap**) freezes under sustained
  hydra load. Short runs (~10 min) survive fine at `-t 2`; a run that goes the *full*
  15-minute cap still exhausts it even at `-t 2`. Same class of issue as the documented
  FW01 Suricata-OOM problem, just on a different box.
- **Bug 2 (software):** `afw scenario watchdog` can **crash instead of cleanly aborting**
  a run if the GNS3 controller API call to power off ATK01 times out. When it crashes,
  the run's journal entry is left permanently stuck as "still running" until someone
  manually runs `afw scenario abort <RUN_ID> "<reason>"` to close it. This happened once
  today; recovered cleanly, but it's a real gap in the watchdog's error handling.

---

## 1. Setup: what was actually on ATK01

Before this session, docs said ATK01 had "nothing but curl." Live inspection showed
tooling had since been added: `nmap`, `hydra`, `sqlmap`, `ffuf`, `curl`, `wget`, `nc`,
`tcpdump`, `python3`, `perl`. No wordlists existed at all (not even a copy of
rockyou-style lists) — only sqlmap's internal tamper data and the system spelling
dictionary.

Fetched a curated SecLists subset (~920 KB total) on the host (which has internet) and
`scp`'d it to `~/wordlists/` on ATK01:
- `creds/`: `top-usernames-shortlist.txt`, `cirt-default-usernames.txt`,
  `top-passwords-shortlist.txt`, `500-worst-passwords.txt`, `10k-most-common.txt`
- `content/`: `common.txt`, `raft-small/medium-directories.txt`,
  `raft-small/medium-files.txt` (for the later `web-content-discovery` scenario)

Note found along the way: `afw lab verify` shows `ATK01 -> 1.1.1.1:443 want=allow
got=open ("ATTACK to Internet (egress allowed)")` — egress internet is actually allowed
from ATK01, which contradicts the isolation-gate doc's description ("clients have no
Internet"). Didn't change anything (wordlists were already fetched via the host), but
worth reconciling the doc with reality.

---

## 2. Attack command used

```bash
hydra -L ~/wordlists/creds/top-usernames-shortlist.txt \
      -P ~/wordlists/creds/500-worst-passwords.txt \
      -s 443 -S \
      'https-post-form://10.77.30.10/login:{"username"\:"^USER^","password"\:"^PASS^"}:H=Content-Type\: application/json:invalid credentials' \
      -t 2
```

Targets the real `POST /login` endpoint (`apps/rental/rental_app.py`, FastAPI + Pydantic
`LoginBody`, JSON body) via hydra's `https-post-form` module. Keep this on hand as the
known-good reference for future `credential_bruteforce`-style runs.

---

## 3. Bug 1 — ATK01 freezes under sustained hydra load

ATK01's spec (`lab/gns3/topology.yaml`): **768 MB RAM, 1 vCPU**. `free -h` on a fresh
boot shows only ~450 MB available and **zero swap**.

**Run 3** (`-t 4`, the first run where syntax actually worked): live risk assessments
showed the detection working excellently — `critical` band, score 93+, `login_rate`
z-score 700+, A3's `account_guessing` flagging 5,000 consecutive failures on one
account. But partway through, ATK01 became unreachable over SSH. Four hydra worker
threads were each sitting at ~130 MB RSS — over 500 MB total on a 768 MB box with no
swap to fall back on. Classic OOM/thrash pattern, same class as the documented FW01
Suricata-OOM issue.

**Fix attempted:** dropped to `-t 2`. This fixed it for **short, manually-stopped runs**
— three test runs of ~8–10 minutes each all completed cleanly with no freeze and stable
memory (`free -h` showed no abnormal growth afterward).

**But it recurred on the validation run**, which (correctly, as the gate run should) ran
its **full 900-second duration** rather than being stopped early. Even at `-t 2`, the
sustained 15 minutes of load froze ATK01 again. So the fix only pushed the threshold out
— it didn't remove it. **Any scenario that runs to its full cap, or any scenario with a
longer cap (`low-and-slow-bruteforce` is 3600 s), should be expected to hit this.**

**Recommendation:** give ATK01 more RAM and/or swap before attempting the longer-duration
scenarios. `-t 1`/`-t 2` buys time but does not solve the underlying constraint.

---

## 4. Bug 2 — the scenario watchdog can crash mid-abort

When run 3 hit its 900 s cap, the watchdog correctly detected the timeout and tried to
power ATK01 off via the GNS3 controller API. That specific call hung and raised an
unhandled exception:

```
/home/gns3/uot/ai-adaptive-firewall/src/afw/lab/gns3.py:53 in _call
    r = self._http.request(method, path, json=body)
httpcore.ReadTimeout: timed out
```

propagating up through `cli.py:_kill_atk01` → `scenarios.py:abort()` → the watchdog's
main loop, **crashing the watchdog process entirely** — it did not retry, did not time
out gracefully, and did not log anything beyond the raw traceback.

**Why this matters:** `scenarios.py:abort()` calls `kill()` *before* it sets
`r.status = ABORTED` and `r.ended_at = now`. Since `kill()` raised, that bookkeeping
never ran. The run's journal entry was left in `RUNNING` state indefinitely — confirmed
by `afw scenario manifest <RUN_ID>` refusing with `ValueError: run has not ended` well
after the VM was actually off.

**How it was recovered (manually, this session):**
1. `afw lab stop ATK01` — confirmed the VM was actually stopped (it was already off;
   the original GNS3 call likely did eventually succeed server-side, the client just
   never got the response back in time).
2. `afw scenario abort <RUN_ID> "<reason>"` — re-run now that ATK01 was already
   stopped, so `kill()` returned immediately (`'ATK01 was not running'`) without
   hitting the same timeout, and the journal was finally closed properly.

This did **not** recur on the later, cleaner watchdog-triggered abort (the validation
run's cap-out was recorded cleanly with no crash) — so the GNS3 API call doesn't fail
every time, only intermittently, plausibly correlated with ATK01 already being
resource-starved and slow to respond at the moment of the stop call. Unconfirmed, but
worth the team's attention regardless: **the watchdog's call to stop ATK01 has no
timeout handling or retry, and a failure there currently crashes the whole watchdog and
can leave a run's journal entry permanently open.**

**Recommendation:** wrap the GNS3 stop call in `_kill_atk01`/`gns3.py:_call` with a
bounded retry, and make `abort()` set `status=ABORTED`/`ended_at` even if `kill()`
raises (or at least in a `finally`), so a flaky power-off never blocks the journal from
closing.

---

## 5. Runs and outcomes

| Run | Window | Outcome | Notes |
|---|---|---|---|
| `run-ed11b3137db4` | 15:27:44–15:45:27Z | ABORTED (watchdog crashed; manually closed) | **Real attack traffic sent**, strong detections observed live (critical, 93+). ATK01 froze (`-t 4`). Watchdog Bug 2 hit here. Manifest logged, not pushed to dataset (irregular termination). |
| `run-0300cccb8fb9` | 15:50:21–16:00:00Z | ✅ ended cleanly | `-t 2`. **Test 1/3** → `atk-bruteforce-20261107-1`, 7,218 obs, 0 FAIL. |
| `run-df477824fe1d` | 16:02:04–16:10:28Z | ✅ ended cleanly | **Test 2/3** → `atk-bruteforce-20261107-2`, 8,932 obs, 0 FAIL. |
| `run-b78d103a5836` | 16:13:09–16:22:52Z | ✅ ended cleanly | **Test 3/3** → `atk-bruteforce-20261107-3`, 9,558 obs, 0 FAIL. |
| `run-30e24469602d` | 16:24:16–16:39:20Z | ABORTED (watchdog, cap — cleanly this time) | **Validation run** → `atk-bruteforce-20261107-validation`, 17,006 obs, 0 FAIL (1 expected `WARN run_aborted`). ATK01 froze again (Bug 1, full-duration run even at `-t 2`). |

Seven benign-background address pairs were used across the session, each new, never
reused: `.200/.201`, `.202/.203`, `.204/.205`, `.206/.207`, `.208/.209`, `.210/.211`,
`.212/.213`. None were ever flagged — zero false positives on benign traffic throughout.

---

## 6. Final dataset state for this family

| Dataset | Purpose | Observations | Validation |
|---|---|---|---|
| `atk-bruteforce-20261107-1` | test | 7,218 | all PASS |
| `atk-bruteforce-20261107-2` | test | 8,932 | all PASS |
| `atk-bruteforce-20261107-3` | test | 9,558 | all PASS |
| `atk-bruteforce-20261107-validation` | validation | 17,006 | all PASS + 1 expected WARN |

`web-bruteforce-login` is complete and ready for `afwc experiment evaluate`. Next in the
predeclared order: `web-sqli-probe` (sqlmap).

---

## 7. Recommendations for the team

1. **Give ATK01 more headroom** (RAM and/or swap) before running anything that goes to
   its full time cap, and especially before `low-and-slow-bruteforce` (1-hour cap) —
   expect the same freeze, just later.
2. **Fix the watchdog's abort path**: add a timeout/retry around the GNS3 stop call, and
   make sure the journal gets marked `ABORTED`/`ended_at` even when the power-off call
   itself fails, so a flaky API call can't leave a run stuck open.
3. Keep the hydra `https-post-form` command in §2 on hand for future
   `credential_bruteforce`-style runs — it's now a known-good reference, field order and
   escaping included.
