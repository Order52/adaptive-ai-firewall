# Faster live learning, 2026-11-18

What changed (see `CHANGELOG.md`, `docs/ADAPTATION_DESIGN.md` §3): a proposal no longer taints a
source unless a policy really changes its traffic; operator feedback `benign_change` /
`false_positive` makes a source learnable within the quarantine time; quarantine 600 to 180 s,
tenure 1800 to 600 s, rate cap 20 to 60 windows per source per hour.

## 1. Why live learning was stuck

Live status before the change: 34 windows seen from the new legitimate user 10.77.20.198, 29 of
them excluded as `tainted`. The database row said why: `taint_reason = policy:rate_limit`, set
when the champion *proposed* a rate limit (monitor mode, never applied). The champion's false
positive therefore stopped the learning that would have corrected it.

## 2. Speed on recorded drift (`adaptation-experiment.json`, `afw experiment adaptation` on CTRL01)

Same recorded run as M4 (751 windows, 6 sources, 45 min), same code, three learner settings:

| Setting | Windows learned | Reference pivots |
|---|---|---|
| conservative defaults (before) | 45 | 0 |
| **fast (now in `config/lab.yaml`)** | **190** | **1** |
| relaxed (labelled experiment, no tenure or rate cap) | 227 | 1 |

The holdout false-positive figures in the same file (champion 0.650, adapted challenger 0.062)
come from the relaxed arm, as in M4; the fast arm's own holdout rate was not measured separately.
The promotion gate still **fails** (no real labelled attack runs; sensitive-feature invariance),
so nothing here changes the live detector.

## 3. Poisoning is unchanged

Poison windows learned (synthetic feature-space windows, nothing sent), compared with the stored
M4 run `m3-2026-10-27/m4-adaptation.json`. These runs use the relaxed arm (tenure and rate caps
removed), which is looser than the fast settings, so the fast settings cannot learn more:

| Case | Learned / offered, M4 (before) | Learned / offered, now |
|---|---|---|
| detectable, 2 colluding sources | 0 / 180 | 0 / 180 |
| in-distribution, 2 sources | 128 / 180 | 128 / 180 |
| in-distribution, 4 sources | 280 / 360 | 280 / 360 |
| detectable, 4 sources | 280 / 360 | 280 / 360 |

Identical, as expected: the corroboration rule (3 or more similar clean sources) is untouched.
In-distribution poison looks benign and 4 colluding sources can corroborate each other: both are
the residual risk already documented (`ADAPTATION_DESIGN.md` §5).

The shorter quarantine (180 s) cannot be tested by offline replay. It is longer than the worst
sensor pause measured (about 118 s, `SLO.md` drill G) and the telemetry latency (0.5 to 2 s).

## 4. Live test on the lab (non-attack traffic only)

Procedure: `POST /api/feedback` (operator token) `benign_change` for 10.77.20.198 (the source
tainted by `policy:rate_limit`) and 10.77.20.199 (new), then 240 s of benign v2 personas
(`traffic/benign_personas.py`, valid routes and credentials) from both addresses.

| Result | Value |
|---|---|
| Windows seen | 49 |
| Excluded as overlap (tumbling windows) | 32 |
| Excluded as `sensitive_range` (a sensitive feature above the profile's q99) | 5 |
| Quarantined, then **learned** (all vouched) | 12 |
| Challenger `n_learned` | 607 to **619** |
| Excluded as `tainted` | **0** (was 29 of 34 before the change) |
| First window: ended 14:11:58, learned 14:14:59 | 181 s, the new quarantine time |

`live-shadow-after.json` is the learner status afterwards.

## 5. Limits, stated plainly

* Twelve windows do not move a model of 600: the live test proves the path works, not that these
  users are now scored normal. A pivot needs about 180 more windows; at the 60-per-hour cap one
  active vouched source gives that in about 3 hours, four sources in under an hour.
* A vouch cannot make a window learnable that fails the evidence or range checks. Five of 17
  candidate windows (29 %) were refused by `sensitive_range`: the lab's legitimate personas
  still produce client-error rates above the profile's q99 (`RESULTS.md` §8 item 8).
* Only the HST arm learns online. Isolation Forest and robust statistics still change only
  through a reviewed batch rebuild, and they drove most of the live proposals.
* Learning is shadow-only. The detector that decides stays the champion until the gate passes and
  an admin promotes; the gate cannot pass without real labelled attack runs (team task).
