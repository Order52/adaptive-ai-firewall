# NV1: network novelty on ordinary network use (protocol)

Status: **protocol, written 2026-10-29 ~03:35Z, before any NV1 data exists.** Results
are added in §7. §1–§6 do not change after the data is collected. Changes made during
development (§4) are recorded with their reason, before the test set is evaluated.

## 1. Problem

The N2 calibration (2026-10-28) used 1,296 windows from web-only users. All were zero
vectors, so every non-web packet counted as "unfamiliar". On 2026-10-29 the live
controller marked USR01's own DNS and NTP traffic unfamiliar 400+ times. A detector with
nothing to compare against cannot separate the normal from the unusual. In addition:

- **DNS answers had the wrong owner** (fixed in `f1b352a`, verified live).
  - Suricata logs an answer from the resolver's side, so it was stored under 1.1.1.1 or
    8.8.8.8.
  - As a result, the resolvers were scored as sources.
  - The client's NXDOMAIN count was always 0, so the NXDOMAIN ceiling could never fire.
  - Dataset capture, which filters by labelled source, dropped every answer.

## 2. What FW01 can and cannot see (2026-10-29)

Suricata runs in pcap mode on two interfaces: vtnet2 (ATTACK, 10.77.10.0/24) and vtnet3
(USERS, 10.77.20.0/24). A packet is seen only if it crosses one of them.

| Traffic | Seen? | Why |
|---|---|---|
| ATTACK or USERS client → WAF01:443 (the app) | yes | crosses vtnet2/vtnet3; the HTTP pipeline also sees it request by request |
| Client → FW01 itself (NTP 123, ICMP, blocked ports) | yes | arrives on the client interface |
| Client → Internet (DNS to public resolvers, HTTPS) | yes | leaves through FW01 from vtnet3/vtnet2 |
| Client → blocked lab zones (DMZ other ports, APP, DB, MGMT) | yes, as failed flows | the SYN arrives on the client interface before pf drops it |
| Client ↔ client inside one segment (e.g. USR01 ↔ another USERS host) | **no** | switched on SW-USERS, never reaches FW01 |
| WAF01 → APP01:8000, APP01 → DB01:5432 | **no** | DMZ/APP/DB interfaces are not inspected |
| Server → server lateral movement (e.g. a compromised WAF01 probing DB01) | **no** | as above |
| Telemetry WAF01/APP01 → CTRL01 | **no** | DMZ/APP → MGMT, not inspected |
| Management → client zones (SSH from the host 10.77.50.254 or CTRL01 into USR01/ATK01) | yes | routed by FW01 out of vtnet2/vtnet3; stored, but from protected sources, so never assessed |
| Management → servers (host or CTRL01 to WAF01/APP01/DB01) | **no** | leaves FW01 on MGMT/DMZ/APP/DB interfaces, none inspected |
| Contents of TLS/SSH sessions | **no** | only SNI, version, sizes, timing and SSH software strings |

**SSH administration.** Clients cannot start SSH anywhere in the lab: "telemetry/SSH
ports are closed to clients" (`afw lab verify`). Legitimate administration starts on
MGMT. Into the client zones it is visible:
- every one of the 41 SSH events stored up to 2026-10-29 03:10Z is management SSH from
  10.77.50.254 or 10.77.50.10 into USR01 or ATK01;
- these are stored but never assessed, because the sources are protected.

**Not done: benign client-initiated SSH.** Generating it would mean opening SSH from
USERS, which weakens the segmentation the project relies on. An SSH flow *initiated
from* a client zone is therefore abnormal by policy, and the fixed ceiling plus "no
benign client SSH" is the correct baseline for client sources.

Sensor expansion is assessed separately (§6.3), after this data is collected; FW01 is
not changed during a capture.

## 3. Data

Generator: `traffic/benign_personas.py` with `AFW_NET=1`, at the commit that adds this
file.
- **What it adds.** Per-user ordinary network use: DNS through public resolvers (2–3 %
  local-name leaks that answer NXDOMAIN), HTTPS/HTTP visits to looked-up sites, NTP and
  ping to the gateway, and an occasional `http://` attempt to the app that fails.
- **User habits.** Each user draws a light, normal or heavy habit (weights 2:3:1).
- **Separation from web traffic.** Web journeys are unchanged and run alongside.

All data is collected in the same 60 min session as the A3 selection data:

| Dataset | Users (10.77.20.x) | Seed | Role |
|---|---|---|---|
| `nv1-train` | .100–.123 (24) | 921 | calibration |
| `nv1-val` | .124–.135 (12) | 922 | development (may be used repeatedly) |
| `a3-sel` + `a3-sel-shift` network events | .140–.161 (22) | 913/914 | **test: unseen users, evaluated once** |

The test users are the A3 selection users. The two uses are independent: network
evaluation never feeds the A3 decision, and A3 never tunes the network detector.

## 4. Detector and development rules

**Detector.** As shipped in N2 (`ml/network_detector.py`):
- a per-quantity benign upper quantile at 1 − α/k (α = 0.01, k = 26, Bonferroni);
- fixed protocol ceilings (ADR-042);
- calibration on every emission of every benign user, zero vectors included
  (`calibration_windows`), now with the DNS fix.

**Development on `nv1-val` only.** A change to the detector is allowed only if:
- it answers a cause demonstrated on `nv1-val`; and
- it is committed with that reason before the test.

Allowed kinds of change: the quantile method, α, which quantities are calibrated, and
how zero vectors are weighted. Ceilings are never raised.

**Freeze.** The calibration and code are committed; then the test runs once.

## 5. Measurements

On `nv1-val` (development) and on the test users (once):

- **Window FPR, unfamiliar.** The share of emissions with any quantity above its
  calibrated level, with a 95 % bootstrap CI over users. Emissions overlap, so users,
  not windows, are resampled.
- **Window FPR, strong.** The share of emissions at a fixed ceiling, and the number of
  users with any strong verdict.
- **Per user.** The share of each user's emissions that are unfamiliar, broken down by
  habit.
- **Drivers.** For each quantity, how often it caused an unfamiliar verdict.
- **Calibration content.** The share of non-zero calibration windows, and the quantiles
  per quantity.

## 6. Criteria and what they allow

### 6.1 On the test users, evaluated once

1. Unfamiliar window FPR ≤ **0.02**, with upper CI ≤ **0.05**.
2. **No** legitimate user receives a strong verdict.

Passing allows the claim: "the network detector has learned normal network use for this
lab population, at a measured false-unfamiliar rate". It does **not** allow any claim
about detecting network attacks, which needs the team's `net-portscan` and SSH-guessing
runs (`TEAM_ATTACK_QUICKSTART.md`).

### 6.2 Mode

The detector stays in **shadow** whatever the result. Moving it towards decisions needs:
- §6.1 passed;
- attack recall measured on team runs;
- a human decision.

### 6.3 Sensor expansion (assessed after the capture)

Inspecting DMZ and APP (vtnet4/vtnet5) would show WAF01→APP01 and APP01→DB01, and
server-side lateral movement. Cost and benefit are measured on FW01 (1 vCPU) before
anything is enabled:
- CPU load and Suricata memory;
- event rate added to CTRL01.

Server sources are management-protected and never enforced against, so they would be
assessed in shadow only. The decision and its measurement are recorded in ADR-042.

*Correction, 2026-10-29 03:55Z (factual, before any NV1 data was read; no criterion
changes):* FW01 has **2 vCPUs** and 1.5 GB RAM, not 1 vCPU. A baseline was measured
during the capture: `artifacts/evidence/nv1-2026-10-29/fw01-load-during-a3-capture.txt`.

## 7. Results

*Recorded 2026-10-29 ~05:40Z. Capture 03:11:16–04:13:00Z (commit `a7d10e7`): all four
datasets validated, observation counts equal to the WAF01 access-log lines for the same
sources. Evidence: `artifacts/evidence/nv1-2026-10-29/`.*

### 7.1 Development (`nv1-val`)

Calibration on `nv1-train` (24 users, 109 615 network events, 2 736 emissions, 2 615
non-zero). Flows, UDP, DNS, bytes and durations are non-zero in 64 % of 60 s and 96 %
of 300 s emissions; SSH never occurs in benign training, so any SSH flow from a user is
unfamiliar by construction.

On `nv1-val` (12 users, 1 368 emissions): unfamiliar **0.0102** [0.0037, 0.0168], strong
0, no user with a strong verdict. No development change was needed and none was made.
Frozen calibration: `dev/nv1-dev1.calibration.json`, sha256 `90a1793b…a877`, commit
`abd0366`.

### 7.2 Test (unseen users `a3-sel` + `a3-sel-shift`, run once): **FAIL**

| Measure | Result | Criterion |
|---|---|---|
| Unfamiliar window FPR (22 users, 2 508 emissions) | **0.0678**, CI [0.0088, 0.1575] | ≤ 0.02, upper CI ≤ 0.05 — **fail** |
| Strong window FPR | 0.0008 [0, 0.0024] | — |
| Users with a strong verdict | **1** (10.77.20.156) | 0 — **fail** |
| Mean unfamiliar share by habit | light 0.006, normal 0.001, heavy **0.240** | — |

Main drivers: `bytes_out_log_300`, `flows_300`, `udp_flows_300`, `dns_queries_300`,
`failed_300`.

The claim of §6.1 is therefore **not** allowed. The detector stays in shadow (§6.2).

### 7.3 Why (post-hoc diagnosis; no re-test)

From `nv1_posthoc_diag.py` / `nv1-posthoc-diag.txt`:

- **Habit coverage.** The unfamiliar verdicts are almost all from heavy users:
  - .156: 85 % of emissions;
  - .154: 27 %;
  - .153: 23 %;
  - .152: 8 %.

  Training had 3 heavy users, with 3.3–4.7 DNS lookups/min. The test had 6, up to
  5.7/min. Light and normal users generalise well, at ≤ 1 % each. A population
  quantile from 24 users does not cover the tail of a habit that only 3 of them showed.
  Per user, the result is correct ("not seen at that level"), but as a rate it is too
  high.
- **Strong verdict.** Heavy user .156 contacted 11, then 10, distinct hosts in 60 s
  (DNS resolver plus visited sites). That meets the fixed host-sweep ceiling of
  `dst_hosts_60` = 10 (ADR-042). The ceiling is too low for legitimate heavy browsing
  in this lab. Under §4, ceilings are never raised within NV1.
- **Display defect found.** The reason text prints the effective level, not the ceiling
  ("ceiling at 7" where the ceiling is 10). The verdict is unaffected; it is fixed
  separately.

### 7.4 What a further attempt needs (not done here)

A new predeclared protocol (NV2), with fresh unseen-user data and none of these sets
reused for testing. It would have to choose, before seeing the data:

- either per-habit or per-user calibration, or a larger and stratified training
  population;
- and a reasoned `dst_hosts_60` ceiling, e.g. one that excludes resolver and NTP
  destinations from the sweep count, with its scan-detection cost stated.

Attack recall is still unmeasured: it needs the team's `net-portscan`, `net-slow-scan`
and `net-ssh-guessing` runs.
