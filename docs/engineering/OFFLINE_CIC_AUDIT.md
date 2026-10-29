# Independent audit of the offline CIC-IDS2017 evaluation

Written 2026-10-29 after the first offline results, in response to a request to audit the
labels and results for leakage before accepting them. **The audit both strengthens and
corrects the first report.** Evidence: `artifacts/evidence/offline-cic-2026-10-29/`
(`cic_audit.py`, `cic-audit-results.json`, `arf-ordering-finding.txt`).

Still a **separate gate** from live GNS3 (`GATE_STATES.md`); nothing here advances gate 1.

## 1. Label audit — is `172.16.0.1` the attacker, and only the attacker?

- CIC-IDS2017's attacker is Kali `205.174.165.73`; `172.16.0.1` is a **firewall/NAT**
  address. In this capture the attacker appears **only** as the post-NAT `172.16.0.1`
  (the original Kali IP never appears as a flow source).
- **What `172.16.0.1` actually does:** every one of its flows goes to the single victim
  `192.168.10.50`, on ports **21 (3,992 flows)**, **22 (2,980)** and 80 (1). It does
  **no other traffic** — it is not a shared NAT carrying benign flows.
- **Temporally:** its activity is confined to **12:00–13:xx UTC** (FTP-Patator) and
  **17:00–18:xx UTC** (SSH-Patator) — the two documented attack windows. There is no
  attacker activity outside them.
- **Conclusion:** labelling `172.16.0.1`'s windows as attack is **temporally and
  behaviourally correct here** — not contaminated by benign-from-NAT. The label is still
  *source-IP-based*, so the real question is the next section.

## 2. Does the model learn behaviour, or just this host/port? (ablation)

The source IP is **not** a feature (only used to label). To test for identity leakage we
retrained the RandomForest on feature subsets (`cic_audit.py`), with a **300 s gap**
between train and test to remove window-overlap leakage (300 s horizon, 30 s step).

| Feature set | Recall | Recall 95% CI | FPR | Precision |
|---|---|---|---|---|
| All features | 0.846 | [0.778, 0.896] | 0.0 | 1.0 |
| **Behaviour only** (no port/host/fan-out) | **0.895** | [0.834, 0.935] | 0.0 | 1.0 |
| **Identity only** (ports/hosts/fan-out) | **0.000** | [0.0, 0.026] | 0.017 | 0.0 |
| Drop `ssh_flows` + `dst_hosts` | 0.923 | [0.868, 0.957] | 0.0 | 1.0 |

- **Behaviour-only is as good or better than all-features; identity-only cannot detect at
  all.** So the detector learns **behaviour, not host/port identity.** The 300 s gap left
  recall unchanged (0.846), so there was **no window-overlap leakage** either.
- **Top features:** connection **durations**, **absence of DNS** (`dns_queries`,
  `dns_names` ≈ 0 for the attacker), destination-port/host counts over 300 s. These are
  genuine automated-brute-force signatures (a Patator run hammers one IP directly, does no
  DNS, with distinctive session durations).
- **Caveat:** "no DNS in the window" is characteristic of a direct-IP brute-forcer and
  could be evaded by a tool that resolves a hostname first. The signal is behavioural, not
  identity, but it is **tool-shaped**.
- **The attack is not trivially "loud":** attacker `failed_60` median 0 (the server
  *answers* each guess, so flows are not "failed"), `flows_60` median 36 vs benign p99 100
  / max 891. Separation comes from a **combination** of features, not one threshold.

## 3. Cross-family generalisation — corrected

| Train → test (withheld) | All features | Behaviour only |
|---|---|---|
| FTP → **SSH** | 0.992 | 0.992 |
| SSH → **FTP** | 0.000 | **0.660** |

The first report's **SSH→FTP 0.0 was a port-feature artifact** — an SSH-trained model
keyed on `ssh_flows` (port 22), which FTP lacks. With behaviour-only features it
generalises to 0.66. So cross-family generalisation is **real but asymmetric and
protocol-shaped**, **not** "universal zero-day detection." Both are brute force on one
dataset; two protocols is not a general claim.

## 4. The RF-vs-ARF comparison — corrected

The first report showed a frozen River ARF at **recall 0.0** and prequential at 0.775, and
implied continuous learning helps. **That was wrong.** Controlled test
(`arf-ordering-finding.txt`), train FTP → test SSH:

| ARF training order | Recall |
|---|---|
| time-ordered (attack in one late burst) | **0.000** |
| **shuffled** (representative order) | **0.976** |
| shuffled, 30 trees | 0.921 |
| shuffled, 10 trees, 20× attack oversample | 0.952 |
| RandomForest (reference) | 0.990 |

**The ARF 0.0 was a data-ordering artifact**, not class imbalance or a defect: Hoeffding
trees commit splits on the long benign prefix before the single late attack burst. With
representative ordering ARF (~0.92–0.98) is **comparable to RF**. **We therefore do not
claim incremental learning is superior**; on this data RF and a fairly-trained ARF are
comparable.

## 5. Audited conclusions (what may and may not be said)

**May be said (offline, external gate only):**
- On real recorded brute force, our feature pipeline + a RandomForest detect the attack at
  **0.846 recall (95% CI [0.78, 0.90])** with **0 false positives on 13,499 benign
  windows** (Wilson upper bound ≈ 0.0003 — *not* "zero FP" in general).
- The detection is **behavioural, not host/port-identity** (ablation), and survives a
  300 s anti-overlap gap.
- A behaviour-only model trained on FTP brute force detects withheld SSH brute force at
  0.99, and SSH→FTP at 0.66 — **cross-protocol generalisation within brute force**, not
  universal zero-day.
- RF and a fairly-trained incremental ARF are **comparable** (~0.85–0.99).

**May NOT be said:**
- Not "universal zero-day detection" (only two brute-force protocols, one dataset).
- Not "zero false positives" beyond the 13,499-window sample (report the CI).
- Not "continuous learning is superior" (the ARF deficit was an ordering artifact).
- Nothing here is **live GNS3** detection (separate gate, BLOCKED).
- These models are **CIC-domain**; they do not transfer to the lab without re-training
  (different benign population).
