# How it all works

A plain-language technical walkthrough: the pipeline, then the AI, then what
"adaptive" actually means. For deeper detail see `ARCHITECTURE.md`; for threats and
mitigations see `THREAT_MODEL.md`; for known limitations see
`SECURITY_AND_LIMITATIONS.md`.

## 1. The lab

A GNS3-simulated network: a firewall (OPNsense), a WAF (reverse proxy), a
real rental-booking app, a database, a desktop/client VM, an attack VM, and a
controller that runs the detection and enforcement logic. Everything is real
software running in real VMs — only the attack *traffic* is scripted rather
than from real internet attackers.

## 2. The pipeline (what happens to a request)

```
Client → Firewall (FW01) → WAF → App → DB
             │                │
             └── mTLS events ─┘──→ Controller
                                      │
                             windowing → 3 detectors → evidence score
                                      │
                               validator (safety checks)
                                      │
                            enforcement (log / propose / auto-apply)
```

1. **Telemetry** — the firewall, WAF, and an IDS each sign and stream events
   to the controller over mTLS.
2. **Windowing** — events are grouped per source IP into short time windows
   (request rate, how many distinct endpoints it hit, error rates, login
   attempts, etc.) — this turns raw logs into a fixed set of numeric
   **features** per window.
3. **Detection** — three models score each window for how unusual it looks.
4. **Evidence score** — the three scores are combined into one 0–100 number
   with a confidence band (`elevated`, `high`, ...). It's called an
   *evidence score*, deliberately not "probability of attack" — it says how
   anomalous the traffic looks, not how guilty the source is.
5. **Validator** — before anything is enforced, a non-ML safety check runs:
   it refuses to ever touch protected/management addresses, caps how much
   can be blocked at once, etc. The ML never talks to the firewall directly.
6. **Enforcement** — depending on mode (below), the proposal is logged,
   sent for human approval, or auto-applied — then the controller verifies
   the change actually took effect on the real firewall (not just "API call
   returned 200").

## 3. The AI — what it actually is

No LLM is involved in detection. It's three classical unsupervised anomaly
detectors, run in parallel per app, each looking at the same features from a
different angle:

| Detector | What it does |
|---|---|
| `robust_stats` | Flags a window if its features are far from the *median* behavior (using MAD, a statistic that isn't thrown off by a few extreme outliers). Cheap, interpretable, good first line of defense. |
| `isolation_forest` (scikit-learn) | Builds random decision trees that try to isolate each point. Anomalies are the points that get isolated in very few splits — they "stick out" in high-dimensional feature space in ways a human-written threshold would miss. |
| `half_space_trees` (River, online) | Same idea as isolation forest, but updates itself incrementally as new windows arrive, instead of needing a batch retrain — this is what lets scoring react to **gradual drift**, not just a fixed snapshot. |

Their outputs are combined into the one evidence score. Three different
detectors catching the same anomaly is stronger evidence than any one of
them alone, and disagreement between them is itself informative.

**No LLM scores traffic.** Claude/MCP only sits on top as an *operator
interface* — a human or an AI agent can ask the system questions ("what's
the current risk?", "what got blocked today?") or propose an action through
the same validated API the dashboard uses. It never bypasses the validator
and never touches the firewall directly.

## 4. How it's "adaptive" — the actual mechanism

This is the part that answers "why isn't this just a fixed ML model":

```
live traffic ──► reputation gate ──► shadow learner ──► drift monitor
                  (excludes sources        │                │
                   already flagged by      │        tracks whether feature
                   WAF/IDS/auth abuse,      │        distributions are moving
                   or under an active       ▼        (ADWIN algorithm)
                   policy, or reported      candidate model
                   as a false positive)    (new "challenger" version,
                                             trained only on clean traffic)
                                                      │
                                           evaluation gate (does the challenger
                                           still catch known attacks? does it
                                           cut false positives? any sign of
                                           being poisoned by fed-in bad data?)
                                                      │
                                              human review ──► promoted to
                                                                live, versioned,
                                                                rollback possible
```

- Every window of live traffic is quietly re-scored by a **shadow model**
  (a "challenger") running alongside the live one — but its output is never
  used for real decisions. It's a continuous, silent experiment.
- A **reputation gate** stops the challenger from learning the wrong
  lesson: any source already confirmed malicious by the WAF, IDS, login
  system, or a human (false-positive feedback) is excluded from training
  data entirely, for 24h. This is the main anti-poisoning defense — an
  attacker can't "teach" the model their traffic is normal just by sending
  a lot of it.
- A **drift monitor** (the ADWIN algorithm) watches whether the statistical
  shape of traffic is genuinely changing over time (new app features, a new
  user segment, seasonal usage) versus just noise.
- If a challenger looks better — catches the same attacks, fewer false
  positives — it goes through an **evaluation gate**, then a **human
  review**, before it's promoted to be the live model. Promotions are
  versioned, so a bad promotion can be rolled back.

**The key design point:** nothing learned from live traffic ever affects a
real enforcement decision until a human has approved its promotion. The
system *proposes* its own improvement; it doesn't silently rewrite itself.
That's the actual safety argument of the whole project.

## 5. The three operating modes

| Mode | Behavior |
|---|---|
| `monitor` | Score everything, act on nothing automatically. (Current default.) |
| `assisted` | Same scoring, but a human must approve/reject each proposal before it's applied. |
| `auto` | Bounded auto-apply, only for low-risk, reversible actions. |

The project currently runs in `monitor` because the live detectors still
have a measurable false-positive rate on genuinely new (but benign) traffic
— shown live, not hidden. That's exactly why the mode tiering and the
promotion gate above exist: the system doesn't get unsupervised authority
over the firewall until it's proven it deserves it.
