# Third independent capture: CIC-IDS2017 Thursday (web attacks + infiltration)

2017-07-06, 9.3 M packets, 8.30 GB (sha256 in `artifacts/evidence/offline-cic-thursday-2026-10-30/`).
Offline, separate gate; nothing here concerns the live GNS3 lab. Behaviour-only features.
Different day, tooling and protocol layer from Tuesday (FTP/SSH brute force) and Friday (scan /
botnet / DDoS). Evidence: `artifacts/evidence/offline-cic-thursday-2026-10-30/`.

## Labels (audited before use — `label-audit.md`)
- Attack = windows from `172.16.0.1` (post-NAT attacker): 3,142 flows, only to the web servers
  192.168.10.50 / .51, mostly port 80. 7 independent attack bursts, 324 windows.
- **Excluded, not labelled**: the infiltration victims 192.168.10.8 (Win Vista, which then ran
  an internal Nmap sweep: 89,036 flows over 1,152 ports) and 192.168.10.25 (Mac), per the UNB
  documentation (https://www.unb.ca/cic/datasets/ids-2017.html). Their traffic mixes benign and
  attack, so an IP label would be wrong either way. 1,762 windows excluded. Consequence: the
  internal-scan phase is **not** evaluated here.

## 1. Cross-capture transfer (ML trained only on Tuesday + Friday)
Recall **0.543** (176/324), block-bootstrap 95 % CI **[0.36, 0.71]**, FPR 0.0 over 7 bursts.
Far better than Tuesday→Friday (0.11): HTTP brute force resembles FTP/SSH brute force
behaviourally. Split by time of day (ML still never saw Thursday): morning web attacks
**0.88** (143/163), afternoon **0.20**.

## 2. Within-Thursday (time split, 300 s gap)
Recall 0.701 (68/97), block CI [0.39, 0.91], FPR 0.0 — only 2 independent bursts in the test
half, so the interval is wide.

## 3. Static Suricata (fair `HOME_NET`) vs ML — see `ERRATUM_STATIC_BASELINE.md`
Whole capture, ML never saw Thursday: morning static 0.28 vs ML 0.88 (union 0.91); afternoon
static 0.04 vs ML 0.20. Static false-positive windows 4–5 %; ML 0.

## 4. Third-family self-learning, 10 seeds, immutable held-out anchors
Old families = Tuesday brute force + Friday attacks; new family = Thursday. Anchor: 3,000 benign,
114 + 32 held-out old-family windows, 130 held-out new-family windows. Mean ± sd:

| Strategy | Benign FPR | Old: Tuesday | Old: Friday | **New: Thursday** | Learn time |
|---|---|---|---|---|---|
| Champion (before) | 0.0016 | 0.952 ± 0.044 | 0.375 ± 0.179 | 0.533 ± 0.193 | — |
| Incremental, no rehearsal | 0.0092 | 1.000 | **0.097 ± 0.137** | 0.881 ± 0.016 | 1.9 s |
| Incremental + rehearsal | 0.0112 | 1.000 | 0.572 ± 0.153 | **0.918 ± 0.030** | 3.6 s |
| Periodic batch RF | **0.0007** | 0.921 | 0.406 ± 0.015 | 0.859 ± 0.042 | **0.24 s** |

- **Learning a third family reproduces** (new-family recall 0.53 → 0.86–0.92), now with 130
  held-out windows rather than 32.
- **Forgetting reproduces**: without rehearsal the weakly-held Friday family drops
  0.375 → 0.097; rehearsal raises it to 0.572; batch retraining holds it at 0.406. (Tuesday is
  retained by all, because Thursday brute force is similar to it.)
- **Batch RF is close to the best at a fraction of the cost**: 0.859 new-family recall at benign
  FPR 0.0007 and 0.24 s, versus 0.918 at FPR 0.0112 and 3.6 s for rehearsal-incremental — about
  6 points of recall for ~16× the false positives and ~15× the compute. **No claim that online
  learning is superior** (`ERRATUM_FORGETTING.md`).

## Limits
One attacker session per family; the held-out Thursday windows come from ~2 bursts; ML is
trained on CIC (cross-capture only for Thursday); the compromised-host phase is excluded; none of
this transfers to the lab without lab-domain data.
